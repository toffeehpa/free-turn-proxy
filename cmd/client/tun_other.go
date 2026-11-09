//go:build !windows

package main

import (
	"errors"

	"github.com/toffeehpa/free-turn-proxy/internal/config"
	"github.com/toffeehpa/free-turn-proxy/internal/logx"
)

func prepareTun(*config.Client, logx.Logger) (*tunHandle, error) {
	return nil, errors.New("-tun: встроенный туннель в CLI есть только на Windows, здесь запустите WireGuard/AmneziaWG отдельно")
}
