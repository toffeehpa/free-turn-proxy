//go:build windows

package winvpn

import (
	"errors"
	"fmt"
	"math"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/toffeehpa/free-turn-proxy/internal/tunnel"
)

// configure раздаёт адаптеру адреса, маршруты AllowedIPs, MTU и DNS. Порядок и
// настройки интерфейса - как у wireguard-windows (tunnel/addressconfig.go).
func configure(luid winipcfg.LUID, cfg *tunnel.Config) error {
	var errs []error
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if err := configureFamily(luid, family, cfg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func configureFamily(luid winipcfg.LUID, family winipcfg.AddressFamily, cfg *tunnel.Config) error {
	routes, hasDefault := routesFor(family, cfg.Peers)
	addrs := prefixesFor(family, cfg.Addresses)
	if len(routes) == 0 && len(addrs) == 0 {
		return nil
	}

	if err := luid.SetRoutesForFamily(family, routes); err != nil {
		return fmt.Errorf("winvpn: set routes: %w", err)
	}
	if err := luid.SetIPAddressesForFamily(family, addrs); err != nil {
		return fmt.Errorf("winvpn: set addresses: %w", err)
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("winvpn: ip interface: %w", err)
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if cfg.MTU > 0 && cfg.MTU <= math.MaxUint16 {
		ipif.NLMTU = uint32(cfg.MTU)
	}
	// Весь трафик в туннель - значит и метрика ниже физической сети.
	if hasDefault {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if err := ipif.Set(); err != nil {
		return fmt.Errorf("winvpn: set mtu and metric: %w", err)
	}

	if err := luid.SetDNS(family, addrsFor(family, cfg.DNS), nil); err != nil {
		return fmt.Errorf("winvpn: set dns: %w", err)
	}
	return nil
}

func routesFor(family winipcfg.AddressFamily, peers []tunnel.Peer) ([]*winipcfg.RouteData, bool) {
	seen := make(map[netip.Prefix]struct{})
	var out []*winipcfg.RouteData
	hasDefault := false
	for i := range peers {
		for _, p := range peers[i].AllowedIPs {
			p = p.Masked()
			if !sameFamily(family, p.Addr()) {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			hasDefault = hasDefault || p.Bits() == 0
			hop := netip.IPv4Unspecified()
			if p.Addr().Is6() {
				hop = netip.IPv6Unspecified()
			}
			out = append(out, &winipcfg.RouteData{Destination: p, NextHop: hop})
		}
	}
	return out, hasDefault
}

func prefixesFor(family winipcfg.AddressFamily, in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if sameFamily(family, p.Addr()) {
			out = append(out, p)
		}
	}
	return out
}

func addrsFor(family winipcfg.AddressFamily, in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		if sameFamily(family, a) {
			out = append(out, a)
		}
	}
	return out
}

func sameFamily(family winipcfg.AddressFamily, a netip.Addr) bool {
	if family == windows.AF_INET {
		return a.Is4()
	}
	return a.Is6()
}
