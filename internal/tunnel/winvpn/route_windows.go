//go:build windows

package winvpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// В x/sys их нет. IPv4 ждёт индекс в сетевом порядке байт, IPv6 - в родном.
const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// routeWatch держит индекс интерфейса с лучшим маршрутом по умолчанию, не считая
// нашего адаптера: к нему и прибиваются сокеты ядра.
type routeWatch struct {
	mu   sync.Mutex
	own  winipcfg.LUID
	idx4 uint32
	idx6 uint32
	cb   *winipcfg.RouteChangeCallback
}

func watchRoutes() (*routeWatch, error) {
	w := &routeWatch{}
	if err := w.refresh(); err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
		if r != nil && r.DestinationPrefix.PrefixLength == 0 {
			_ = w.refresh()
		}
	})
	if err != nil {
		return nil, fmt.Errorf("winvpn: route callback: %w", err)
	}
	w.cb = cb
	return w, nil
}

// exclude убирает наш адаптер из выбора: после подъёма его 0.0.0.0/0 с метрикой 0
// всегда был бы лучшим.
func (w *routeWatch) exclude(luid winipcfg.LUID) {
	w.mu.Lock()
	w.own = luid
	w.mu.Unlock()
	_ = w.refresh()
}

func (w *routeWatch) refresh() error {
	w.mu.Lock()
	own := w.own
	w.mu.Unlock()

	idx4, err4 := bestDefault(windows.AF_INET, own)
	idx6, err6 := bestDefault(windows.AF_INET6, own)

	w.mu.Lock()
	w.idx4, w.idx6 = idx4, idx6
	w.mu.Unlock()
	if err4 != nil && err6 != nil {
		return errors.Join(err4, err6)
	}
	return nil
}

func bestDefault(family winipcfg.AddressFamily, own winipcfg.LUID) (uint32, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, fmt.Errorf("winvpn: route table: %w", err)
	}
	best, bestMetric := uint32(0), uint32(math.MaxUint32)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == own {
			continue
		}
		ifRow, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !ifRow.Connected {
			continue
		}
		// Windows сравнивает сумму метрик маршрута и интерфейса - так же и тут.
		if m := r.Metric + ifRow.Metric; m < bestMetric {
			best, bestMetric = r.InterfaceIndex, m
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("winvpn: no default route for family %d", family)
	}
	return best, nil
}

// protect привязывает сокет к физическому интерфейсу. Семейство сокета не знаем,
// поэтому ставим оба варианта: хватит того, что подошёл.
func (w *routeWatch) protect(fd int) bool {
	w.mu.Lock()
	idx4, idx6 := w.idx4, w.idx6
	w.mu.Unlock()

	s := windows.Handle(fd)
	ok := false
	if idx4 != 0 {
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], idx4)
		v := int(binary.NativeEndian.Uint32(be[:]))
		ok = windows.SetsockoptInt(s, windows.IPPROTO_IP, ipUnicastIF, v) == nil
	}
	if idx6 != 0 && windows.SetsockoptInt(s, windows.IPPROTO_IPV6, ipv6UnicastIF, int(idx6)) == nil {
		ok = true
	}
	return ok
}

func (w *routeWatch) close() {
	if w.cb != nil {
		_ = w.cb.Unregister()
	}
}
