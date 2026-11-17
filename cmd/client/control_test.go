package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/toffeehpa/free-turn-proxy/internal/logx"
)

func TestOpenControlWithoutPath(t *testing.T) {
	ctl, err := openControl("", logx.Nop())
	if err != nil || ctl != nil {
		t.Fatalf("openControl(\"\") = %v, %v; want nil, nil", ctl, err)
	}
	if ctl.solver() == nil {
		t.Fatal("solver() = nil without -control")
	}
}

// Канал не создаём: его готовит хост, который ждёт на другом конце.
func TestOpenControlNeedsExisting(t *testing.T) {
	if _, err := openControl(filepath.Join(t.TempDir(), "nope"), logx.Nop()); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestControlCaptchaEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctl, err := openControl(path, logx.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctl.captcha("http://localhost:8765/x")
	ctl.captcha("")

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event":"captcha","url":"http://localhost:8765/x"}` + "\n" + `{"event":"captcha","url":""}` + "\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
