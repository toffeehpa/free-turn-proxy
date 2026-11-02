// Package sfu - канал ядра через SFU звонка VK. Движок vkcalls и транспорт vp8channel
// взяты из olcRTC (см. NOTICE), здесь только склейка: датаграммы ядра едут в видеотреке
// звонка от клиента до моста на другой стороне комнаты.
package sfu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/toffeehpa/free-turn-proxy/internal/sfu/engine/builtin"
	"github.com/toffeehpa/free-turn-proxy/internal/sfu/logger"
	"github.com/toffeehpa/free-turn-proxy/internal/sfu/protect"
	"github.com/toffeehpa/free-turn-proxy/internal/sfu/transport"
	"github.com/toffeehpa/free-turn-proxy/internal/sfu/transport/vp8channel"
)

const (
	DefaultDNS = "77.88.8.8:53"
	DefaultFPS = 120

	helloMsg      = "ft-hello\n"
	peerPrefix    = "ft-peer "
	helloInterval = 2 * time.Second

	pingInterval = 5 * time.Second
	pingTimeout  = 20 * time.Second
)

// Пинг идёт датаграммой рядом с трафиком ядра. Первый байт 0xff не бывает ни у
// WireGuard, ни у DTLS, ни у RTP-обфускации, так что с данными не путается.
var (
	pingMsg = []byte{0xff, 'f', 't', 'p', 'i'}
	pongMsg = []byte{0xff, 'f', 't', 'p', 'o'}
)

var (
	ErrUnsupported = errors.New("sfu: transport lacks datagram or control plane")
	ErrClosed      = errors.New("sfu: closed")
)

var setupOnce sync.Once

func setup() {
	setupOnce.Do(func() {
		builtin.RegisterDefaults()
		logger.DisableNoisyPionLogs()
	})
}

// Кадр уходит раз в 1/fps, и датаграмма ждёт ближайшего - это прямая прибавка к пингу.
func linkConfig(room, dns string, fps, batch int) transport.Config {
	if dns == "" {
		dns = DefaultDNS
	}
	cfg := transport.Config{
		Provider:  "vkcalls",
		RoomURL:   room,
		DNSServer: dns,
		Resolver:  protect.NewResolver(dns),
	}
	if fps <= 0 {
		fps = DefaultFPS
	}
	cfg.Options = vp8channel.Options{FPS: fps, BatchSize: batch}
	return cfg
}

// Client - сторона клиента: один мост в комнате, датаграммы только ему.
type Client struct {
	ln     transport.Transport
	dg     transport.DatagramTransport
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	lastPong atomic.Int64
}

// Dial заходит в комнату и ждёт ответа моста. ctx ограничивает только вход: живёт
// канал до Close или до конца звонка.
func Dial(ctx context.Context, room, dns string, fps, batch int, onData func([]byte)) (*Client, error) {
	setup()
	lctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &Client{cancel: cancel, done: make(chan struct{})}

	cfg := linkConfig(room, dns, fps, batch)
	cfg.OnDatagram = func(data []byte) {
		if bytes.Equal(data, pongMsg) {
			c.lastPong.Store(time.Now().UnixNano())
			return
		}
		onData(data)
	}
	ln, err := vp8channel.New(lctx, cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sfu: open link: %w", err)
	}
	c.ln = ln
	dg, okDG := ln.(transport.DatagramTransport)
	cp, okCP := ln.(transport.ControlPlane)
	id, okID := ln.(transport.PeerIdentity)
	if !okDG || !okCP || !okID {
		_ = c.Close()
		return nil, ErrUnsupported
	}
	c.dg = dg

	// Переподключение движка меняет эпохи, привязка к мосту теряется - отдаём это
	// сессии ядра, она сама перезайдёт.
	ln.SetShouldReconnect(func() bool { return false })
	ln.SetEndedCallback(func(string) { _ = c.Close() })
	ln.SetReconnectCallback(func() { _ = c.Close() })

	peer := make(chan string, 1)
	cp.SetControlOnData(lineReader(func(line string) {
		if p, ok := strings.CutPrefix(line, peerPrefix); ok {
			select {
			case peer <- p:
			default:
			}
		}
	}))

	if err := ln.Connect(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("sfu: connect: %w", err)
	}
	go ln.WatchConnection(lctx)

	if err := c.waitBridge(ctx, cp, id, peer); err != nil {
		_ = c.Close()
		return nil, err
	}
	c.lastPong.Store(time.Now().UnixNano())
	go c.watch()
	return c, nil
}

// waitBridge шлёт привет, пока мост не назовёт свою эпоху, и привязывается к ней.
func (c *Client) waitBridge(ctx context.Context, cp transport.ControlPlane, id transport.PeerIdentity, peer <-chan string) error {
	t := time.NewTicker(helloInterval)
	defer t.Stop()
	for {
		if cp.ControlCanSend() {
			_ = cp.ControlSend([]byte(helloMsg))
		}
		select {
		case p := <-peer:
			if err := id.ConfirmPeer(p); err != nil {
				return fmt.Errorf("sfu: confirm bridge: %w", err)
			}
			return nil
		case <-c.done:
			return ErrClosed
		case <-ctx.Done():
			return fmt.Errorf("sfu: wait bridge: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// Мост мог перезапуститься с новой эпохой, а движок в комнате этого не заметит:
// датаграммы уходят старой эпохе в никуда. Без понга закрываемся, сессия перезайдёт.
func (c *Client) watch() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, c.lastPong.Load())) > pingTimeout {
				_ = c.Close()
				return
			}
			_ = c.dg.SendDatagram(pingMsg)
		}
	}
}

func (c *Client) Send(data []byte) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	return c.dg.SendDatagram(data)
}

func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.cancel()
		if c.ln != nil {
			_ = c.ln.Close()
		}
	})
	return nil
}

// Bridge - сторона сервера: отвечает на привет каждого клиента и раздаёт датаграммы по пирам.
type Bridge struct {
	ln     transport.Transport
	dg     transport.PeerDatagramTransport
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func Serve(ctx context.Context, room, dns string, fps, batch int, onData func(peer string, data []byte)) (*Bridge, error) {
	setup()
	lctx, cancel := context.WithCancel(ctx)
	b := &Bridge{cancel: cancel, done: make(chan struct{})}

	cfg := linkConfig(room, dns, fps, batch)
	cfg.OnPeerData = func(string, []byte) {}
	cfg.OnPeerDatagram = func(peer string, data []byte) {
		if bytes.Equal(data, pingMsg) {
			if b.dg != nil {
				_ = b.dg.SendDatagramTo(peer, pongMsg)
			}
			return
		}
		onData(peer, data)
	}
	ln, err := vp8channel.New(lctx, cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sfu: open link: %w", err)
	}
	b.ln = ln
	dg, okDG := ln.(transport.PeerDatagramTransport)
	cp, okCP := ln.(transport.PeerControlPlane)
	id, okID := ln.(transport.PeerIdentity)
	if !okDG || !okCP || !okID {
		_ = b.Close()
		return nil, ErrUnsupported
	}
	b.dg = dg

	ln.SetShouldReconnect(func() bool { return lctx.Err() == nil })
	ln.SetEndedCallback(func(string) { _ = b.Close() })

	var mu sync.Mutex
	readers := map[string]func([]byte){}
	cp.SetControlOnPeerData(func(peer string, data []byte) {
		mu.Lock()
		r, ok := readers[peer]
		if !ok {
			r = lineReader(func(line string) {
				if line+"\n" == helloMsg {
					_ = cp.ControlSendTo(peer, []byte(peerPrefix+id.LocalPeerID()+"\n"))
				}
			})
			readers[peer] = r
		}
		mu.Unlock()
		r(data)
	})

	if err := ln.Connect(ctx); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("sfu: connect: %w", err)
	}
	go ln.WatchConnection(lctx)
	return b, nil
}

func (b *Bridge) SendTo(peer string, data []byte) error { return b.dg.SendDatagramTo(peer, data) }

func (b *Bridge) Done() <-chan struct{} { return b.done }

func (b *Bridge) Close() error {
	b.once.Do(func() {
		close(b.done)
		b.cancel()
		if b.ln != nil {
			_ = b.ln.Close()
		}
	})
	return nil
}

// Управляющий канал - поток KCP, границы сообщений он не держит.
func lineReader(onLine func(string)) func([]byte) {
	var mu sync.Mutex
	var buf []byte
	return func(data []byte) {
		mu.Lock()
		buf = append(buf, data...)
		var lines []string
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			lines = append(lines, string(buf[:i]))
			buf = buf[i+1:]
		}
		if len(buf) > 512 {
			buf = nil
		}
		mu.Unlock()
		for _, l := range lines {
			onLine(l)
		}
	}
}
