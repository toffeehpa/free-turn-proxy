package main

import (
	"runtime"
	"testing"

	"github.com/toffeehpa/free-turn-proxy/internal/config"
	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel"
)

func TestSetupTunWithoutFlagKeepsExternalWG(t *testing.T) {
	cfg := &config.Client{Tunnel: config.TunnelOpts{Mode: tunnel.ModeWG, Config: "x", MTU: 1280}}
	vpn, err := setupTun(cfg, logx.Nop())
	if err != nil || vpn != nil {
		t.Fatalf("setupTun = %v, %v; want nil, nil", vpn, err)
	}
	if cfg.Tunnel.Mode != tunnel.ModeNone {
		t.Fatalf("mode = %q, want %q", cfg.Tunnel.Mode, tunnel.ModeNone)
	}
}

func TestSetupTunNeedsTunnelConfig(t *testing.T) {
	if _, err := setupTun(&config.Client{Tun: true}, logx.Nop()); err == nil {
		t.Fatal("-tun без конфига туннеля должен падать")
	}
}

func TestSetupTunOnlyOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на Windows поднимает настоящий адаптер")
	}
	cfg := &config.Client{Tun: true, Tunnel: config.TunnelOpts{Mode: tunnel.ModeWG, Config: "x", MTU: 1280}}
	if _, err := setupTun(cfg, logx.Nop()); err == nil {
		t.Fatal("-tun вне Windows должен падать")
	}
}
