//go:build windows

package main

import (
	"github.com/toffeehpa/free-turn-proxy/internal/config"
	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel/winvpn"
)

func prepareTun(cfg *config.Client, logger logx.Logger) (*tunHandle, error) {
	t, err := winvpn.Prepare(cfg.Tunnel, logger)
	if err != nil {
		return nil, err
	}
	return &tunHandle{
		pipe:    t.LocalPipe,
		upFn:    func() error { return t.Up(logger) },
		closeFn: t.Close,
	}, nil
}
