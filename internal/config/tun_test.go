package config

import (
	"io"
	"testing"

	"github.com/toffeehpa/free-turn-proxy/internal/tunnel"
)

func TestParseClientTunConfEnablesTunnel(t *testing.T) {
	args := append(validClientArgs(), "-tun", "-tun-conf", "[Interface]\nPrivateKey = x")
	c, err := ParseClient(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Tun || c.Tunnel.Mode != tunnel.ModeAWG || c.Tunnel.Config == "" {
		t.Fatalf("tun = %v, tunnel = %+v; want -tun и awg с конфигом", c.Tun, c.Tunnel)
	}
}

// Без -tun-conf туннель по-прежнему выключен, даже с -tun: ошибку даёт клиент.
func TestParseClientTunWithoutConf(t *testing.T) {
	c, err := ParseClient(append(validClientArgs(), "-tun"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tunnel.Enabled() {
		t.Fatalf("tunnel = %+v, want выключен", c.Tunnel)
	}
}
