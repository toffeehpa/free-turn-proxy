// sfubridge - вторая сторона -provider sfu: сидит в звонке VK и раздаёт датаграммы клиентов
// серверу обычным UDP, по сокету на клиента. Сам сервер про SFU не знает.
//
// Мост общается с VK, поэтому запускать его стоит там, где VK не видит адрес сервера
// (например, в netns с WARP), а -forward указывает на сервер через veth.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/sfu"
	"github.com/toffeehpa/free-turn-proxy/internal/shutdown"
)

var version = "dev"

const (
	idleTimeout = 3 * time.Minute
	readBuf     = 64 * 1024
)

func main() {
	fs := flag.NewFlagSet("sfubridge", flag.ContinueOnError)
	room := fs.String("room", "", "ссылка VK Calls: https://vk.ru/call/join/...")
	forward := fs.String("forward", "127.0.0.1:56000", "адрес сервера free-turn-proxy (UDP)")
	dns := fs.String("dns", "1.1.1.1:53", "DNS для VK API")
	fps := fs.Int("fps", 0, "кадров в секунду видеотрека; 0 - дефолт (120). Выше - меньше пинг")
	batch := fs.Int("batch", 0, "пакетов в одном кадре; 0 - дефолт (64). Меньше - ровнее пинг под нагрузкой")
	debug := fs.Bool("debug", false, "подробный лог")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	logger := logx.New(*debug)
	logger.Infof("Free Turn Proxy sfubridge version=%s", version)
	if *room == "" {
		logger.Errorf("-room is required")
		os.Exit(2)
	}
	dst, err := net.ResolveUDPAddr("udp", *forward)
	if err != nil {
		logger.Errorf("resolve forward: %v", err)
		os.Exit(2)
	}

	ctx, stop := shutdown.Watch(context.Background(), logger)
	defer stop()

	for ctx.Err() == nil {
		if err := run(ctx, *room, *dns, *fps, *batch, dst, logger); err != nil && ctx.Err() == nil {
			logger.Warnf("bridge: %v, retry in 5s", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

type peerConn struct {
	conn *net.UDPConn
	last time.Time
}

func run(ctx context.Context, room, dns string, fps, batch int, dst *net.UDPAddr, logger logx.Logger) error {
	var (
		mu    sync.Mutex
		peers = map[string]*peerConn{}
		br    *sfu.Bridge
		ready = make(chan struct{})
	)
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	onData := func(peer string, data []byte) {
		<-ready
		mu.Lock()
		p, ok := peers[peer]
		if !ok {
			c, err := net.DialUDP("udp", nil, dst)
			if err != nil {
				mu.Unlock()
				logger.Warnf("peer %s: dial forward: %v", peer, err)
				return
			}
			p = &peerConn{conn: c}
			peers[peer] = p
			logger.Infof("peer %s joined (%d total)", peer, len(peers))
			go pump(rctx, br, peer, c, logger)
		}
		p.last = time.Now()
		mu.Unlock()
		_, _ = p.conn.Write(data)
	}

	b, err := sfu.Serve(rctx, room, dns, fps, batch, onData)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	br = b
	close(ready)
	defer func() {
		_ = b.Close()
		mu.Lock()
		for _, p := range peers {
			_ = p.conn.Close()
		}
		mu.Unlock()
	}()
	logger.Infof("bridge in room, forwarding to %s", dst)

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-rctx.Done():
			return nil
		case <-b.Done():
			return errors.New("link ended")
		case <-t.C:
			mu.Lock()
			for id, p := range peers {
				if time.Since(p.last) > idleTimeout {
					_ = p.conn.Close()
					delete(peers, id)
					logger.Infof("peer %s idle, dropped", id)
				}
			}
			mu.Unlock()
		}
	}
}

func pump(ctx context.Context, b *sfu.Bridge, peer string, c *net.UDPConn, logger logx.Logger) {
	buf := make([]byte, readBuf)
	for ctx.Err() == nil {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if err := b.SendTo(peer, buf[:n]); err != nil {
			logger.Debugf("peer %s: send: %v", peer, err)
		}
	}
}
