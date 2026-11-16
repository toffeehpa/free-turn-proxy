package vkauth

import (
	"context"
	"net"

	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk/internal/captcha"

	tlsclient "github.com/bogdanfinn/tls-client"
)

type CaptchaSolveMode int

const (
	CaptchaSolveModeAuto CaptchaSolveMode = iota
	CaptchaSolveModeManual
)

// Две попытки авторешателя, каждая с новой персоной: на череду провалов VK
// отвечает ERROR_LIMIT на весь IP.
const captchaAutoAttempts = 2

func CaptchaSolveModeForAttempt(attempt int, manualOnly bool) (CaptchaSolveMode, bool) {
	if manualOnly {
		return CaptchaSolveModeManual, attempt == 0
	}
	switch {
	case attempt < captchaAutoAttempts:
		return CaptchaSolveModeAuto, true
	case attempt == captchaAutoAttempts:
		return CaptchaSolveModeManual, true
	}
	return 0, false
}

func nextAttemptVerb(cur, next CaptchaSolveMode) string {
	if cur == next {
		return "Retrying"
	}
	return "Falling back to"
}

func CaptchaSolveModeLabel(mode CaptchaSolveMode) string {
	switch mode {
	case CaptchaSolveModeAuto:
		return "auto captcha"
	case CaptchaSolveModeManual:
		return "manual captcha"
	default:
		return "captcha"
	}
}

type AutoSolveFunc func(
	ctx context.Context,
	captchaErr *captcha.Error,
	streamID int,
	http tlsclient.HttpClient,
	profile browserprofile.Profile,
) (token string, err error)

type ManualSolveFunc func(
	ctx context.Context,
	captchaErr *captcha.Error,
	dialer net.Dialer,
	profile browserprofile.Profile,
) (token string, err error)
