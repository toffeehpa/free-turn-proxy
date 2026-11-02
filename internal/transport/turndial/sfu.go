package turndial

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/toffeehpa/free-turn-proxy/internal/sfu"
)

const sfuQueue = 1024

// SFU - поток через SFU звонка вместо TURN-аллокации. Датаграммы едут в видеотреке до
// моста (cmd/sfubridge), а мост отдаёт их серверу обычным UDP, так что сервер не меняется.
func SFU(ctx context.Context, room, dns string, fps, batch int, peer *net.UDPAddr) (*Stream, error) {
	c := &sfuConn{peer: peer, in: make(chan []byte, sfuQueue), deadline: make(chan struct{})}
	cl, err := sfu.Dial(ctx, room, dns, fps, batch, c.push)
	if err != nil {
		return nil, fmt.Errorf("sfu dial: %w", err)
	}
	c.cl = cl
	return &Stream{
		Relay:         c,
		ServerUDPAddr: peer,
		PermDead:      cl.Done(),
		close:         cl.Close,
	}, nil
}

type sfuConn struct {
	cl   *sfu.Client
	peer *net.UDPAddr
	in   chan []byte

	mu       sync.Mutex
	timer    *time.Timer
	deadline chan struct{}
}

func (c *sfuConn) push(data []byte) {
	select {
	case c.in <- append([]byte(nil), data...):
	default:
	}
}

func (c *sfuConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	select {
	case b := <-c.in:
		return copy(p, b), c.peer, nil
	case <-c.cl.Done():
		return 0, nil, net.ErrClosed
	case <-dl:
		return 0, nil, timeoutError{}
	}
}

func (c *sfuConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.cl.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *sfuConn) Close() error { return c.cl.Close() }

func (*sfuConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *sfuConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (*sfuConn) SetWriteDeadline(time.Time) error { return nil }

func (c *sfuConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	ch := make(chan struct{})
	c.deadline = ch
	if t.IsZero() {
		return nil
	}
	if d := time.Until(t); d > 0 {
		c.timer = time.AfterFunc(d, func() { close(ch) })
	} else {
		close(ch)
	}
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "sfu: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
