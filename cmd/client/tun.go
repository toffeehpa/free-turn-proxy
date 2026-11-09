package main

import (
	"errors"
	"net"

	"github.com/toffeehpa/free-turn-proxy/internal/config"
	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk"
	"github.com/toffeehpa/free-turn-proxy/internal/session"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel"
)

// tunHandle - встроенный туннель клиента: pipe уходит сессии вместо локального UDP.
type tunHandle struct {
	pipe    net.PacketConn
	upFn    func() error
	closeFn func()
}

func (h *tunHandle) up() error { return h.upFn() }

// close терпит nil: вызывается на всех путях выхода, туннель есть не всегда.
func (h *tunHandle) close() {
	if h != nil {
		h.closeFn()
	}
}

// setupTun разбирает -tun и конфиг туннеля из ссылки; без -tun туннель, как и
// раньше, поднимает отдельный WireGuard/AmneziaWG.
func setupTun(cfg *config.Client, logger logx.Logger) (*tunHandle, error) {
	switch {
	case cfg.Tun && cfg.Tunnel.Enabled():
		return prepareTun(cfg, logger)
	case cfg.Tun:
		return nil, errors.New("-tun: в ссылке нет конфига туннеля")
	case cfg.Tunnel.Enabled():
		logger.Warnf("ссылка содержит конфиг %s: CLI встроенный туннель не поднимает, запустите WireGuard/AmneziaWG отдельно", cfg.Tunnel.Mode)
		cfg.Tunnel.Mode = tunnel.ModeNone
	}
	return nil, nil //nolint:nilnil // туннеля нет - не ошибка
}

// newSession: адаптер поднимаем после session.New - до него конфиг сессии мог
// не пройти, а маршрут 0.0.0.0/0 уже отрезал бы машину от сети.
func newSession(cfg *config.Client, vpn *tunHandle, logger logx.Logger) (*session.Session, error) {
	deps := session.Deps{
		Logger: logger,
		Solver: vk.DefaultManualSolver,
	}
	if vpn != nil {
		deps.LocalPipe = vpn.pipe
	}
	sess, err := session.New(cfg, deps)
	if err != nil {
		vpn.close()
		return nil, err
	}
	if vpn != nil {
		if err := vpn.up(); err != nil {
			vpn.close()
			return nil, err
		}
	}
	return sess, nil
}
