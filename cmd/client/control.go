package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/toffeehpa/free-turn-proxy/internal/logx"
	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk"
)

// control - push-канал событий для хоста, по строке JSON на событие.
type control struct {
	mu  sync.Mutex
	w   io.Writer
	log logx.Logger
}

type controlEvent struct {
	Event string `json:"event"`
	URL   string `json:"url"`
}

func openControl(path string, logger logx.Logger) (*control, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // без -control канала нет - не ошибка
	}
	// Без O_CREATE: named pipe открывается только как существующий.
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // путь даёт хост
	if err != nil {
		return nil, fmt.Errorf("-control: %w", err)
	}
	return &control{w: f, log: logger}, nil
}

func (c *control) send(ev controlEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(append(b, '\n')); err != nil {
		c.log.Warnf("-control: %v", err)
	}
}

// captcha передаёт URL для решения капчи вручную (пустой url - закрыть окно).
func (c *control) captcha(url string) { c.send(controlEvent{Event: "captcha", URL: url}) }

// solver: браузер открывает хост - у ядра под службой Windows рабочего стола нет.
func (c *control) solver() vk.ManualSolverFunc {
	if c == nil {
		return vk.DefaultManualSolver
	}
	return vk.ProxyManualSolver(c.captcha, func() { c.captcha("") })
}
