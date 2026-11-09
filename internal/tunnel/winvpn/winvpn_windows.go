//go:build windows

package winvpn

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/toffeehpa/free-turn-proxy/internal/config"
	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/netconn"
	"github.com/toffeehpa/free-turn-proxy/internal/netctl"
	sfuprotect "github.com/toffeehpa/free-turn-proxy/internal/sfu/protect"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel/awg"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel/bind"
	"github.com/toffeehpa/free-turn-proxy/internal/tunnel/wgconf"
)

// AdapterName - имя адаптера Wintun в списке сетевых подключений.
const AdapterName = "FreeTurn"

// pipeHeadroom - запас под заголовки WireGuard и junk AmneziaWG, как в mobile.
const pipeHeadroom = 512

var ErrProtect = errors.New("winvpn: socket bind to physical interface failed") //nolint:gochecknoglobals // sentinel для errors.Is

// Tunnel - поднятый туннель. LocalPipe отдаётся сессии вместо локального UDP.
type Tunnel struct {
	LocalPipe net.PacketConn

	cfg        *tunnel.Config
	routes     *routeWatch
	backend    *awg.Backend
	bind       *bind.SinglePeerBind
	deviceSide net.PacketConn
}

// Prepare разбирает конфиг и привязывает сокеты ядра к физической сети. Вызывать
// до session.New: первые же походы в VK API должны идти мимо будущего туннеля.
func Prepare(opts config.TunnelOpts, logger logx.Logger) (*Tunnel, error) {
	cfg, err := wgconf.Parse(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("winvpn: parse tunnel config: %w", err)
	}
	if opts.MTU > 0 {
		cfg.MTU = opts.MTU
	}
	if opts.Mode == tunnel.ModeWG && cfg.Amnezia.Enabled() {
		logger.Warnf("tunnel: mode=wg, параметры AmneziaWG из конфига игнорируются")
		cfg.Amnezia = tunnel.AmneziaParams{}
	}
	// Пир один - сервер за сессией, адрес ему не нужен.
	for i := range cfg.Peers {
		cfg.Peers[i].Endpoint = ""
	}

	rw, err := watchRoutes()
	if err != nil {
		return nil, err
	}
	installProtect(rw)

	deviceSide, relaySide := netconn.PacketPipe(cfg.MTU+pipeHeadroom, 0)
	b := bind.NewSinglePeerBind(deviceSide)
	return &Tunnel{
		LocalPipe:  relaySide,
		cfg:        cfg,
		routes:     rw,
		backend:    awg.New(awg.Deps{Bind: b, Log: logger}),
		bind:       b,
		deviceSide: deviceSide,
	}, nil
}

// Up создаёт адаптер, поднимает WireGuard и раздаёт адреса и маршруты. Нужны права
// администратора и wintun.dll рядом с бинарём.
func (t *Tunnel) Up(logger logx.Logger) error {
	dev, err := tun.CreateTUN(AdapterName, t.cfg.MTU)
	if err != nil {
		return fmt.Errorf("winvpn: create wintun adapter (нужны права администратора и wintun.dll): %w", err)
	}
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		_ = dev.Close()
		return errors.New("winvpn: unexpected tun device type")
	}
	luid := winipcfg.LUID(native.LUID())
	t.routes.exclude(luid)

	if err := t.backend.UpDevice(t.cfg, dev); err != nil {
		return err
	}
	if err := configure(luid, t.cfg); err != nil {
		_ = t.backend.Down()
		return err
	}
	logger.Infof("tunnel: adapter %s up", AdapterName)
	return nil
}

func (t *Tunnel) Stats() (tunnel.Stats, error) { return t.backend.Stats() }

// Close снимает туннель; Windows сама убирает адреса и маршруты вместе с адаптером.
func (t *Tunnel) Close() {
	if t == nil {
		return
	}
	// Bind первым - иначе device.Close() ждёт читающую горутину (см. mobile).
	_ = t.bind.Close()
	_ = t.backend.Down()
	_ = t.deviceSide.Close()
	_ = t.LocalPipe.Close()
	netctl.SetControl(nil)
	sfuprotect.SetProtector(nil)
	t.routes.close()
}

func installProtect(rw *routeWatch) {
	// Сокеты pion в SFU-канале создаются мимо netctl - им свой хук, как в mobile.
	sfuprotect.SetProtector(rw.protect)
	netctl.SetControl(func(_, _ string, c syscall.RawConn) error {
		ok := false
		if err := c.Control(func(fd uintptr) { ok = rw.protect(int(fd)) }); err != nil {
			return fmt.Errorf("socket control: %w", err)
		}
		if !ok {
			return ErrProtect
		}
		return nil
	})
}
