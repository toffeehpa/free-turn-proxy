package manual

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRunCaptchaServerPresentsAfterListen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keyCh := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ready")
	})
	present := func(captchaURL string) {
		response, err := http.Get(captchaURL) //nolint:gosec,noctx // local test server
		if err != nil {
			t.Errorf("present called before server was ready: %v", err)
			keyCh <- "failed"
			return
		}
		_ = response.Body.Close()
		keyCh <- "token"
	}

	got, err := runCaptchaServerAndWait(ctx, handler, localCaptchaOrigin(), keyCh, "test", present)
	if err != nil {
		t.Fatal(err)
	}
	if got != "token" {
		t.Fatalf("token = %q, want token", got)
	}
}

func TestRewriteProxyRedirectLocation(t *testing.T) {
	t.Parallel()

	targetURL, err := url.Parse("https://id.vk.ru/captcha")
	if err != nil {
		t.Fatalf("failed to parse target URL: %v", err)
	}

	testCases := []struct {
		name     string
		location string
		want     string
		ok       bool
	}{
		{
			name:     "keeps safe relative path",
			location: "/captcha?step=2",
			want:     "/captcha?step=2",
			ok:       true,
		},
		{
			name:     "rewrites same-origin absolute URL",
			location: "https://id.vk.ru/captcha?step=2",
			want:     "http://localhost:8765/captcha?step=2",
			ok:       true,
		},
		{
			name:     "blocks scheme-relative redirect",
			location: "//evil.example/captcha",
			ok:       false,
		},
		{
			name:     "blocks slash-backslash redirect",
			location: `/\evil.example/captcha`,
			ok:       false,
		},
		{
			name:     "blocks lookalike absolute host",
			location: "https://id.vk.ru.evil.example/captcha",
			ok:       false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := rewriteProxyRedirectLocation(tc.location, targetURL)
			if ok != tc.ok {
				t.Fatalf("rewriteProxyRedirectLocation() ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("rewriteProxyRedirectLocation() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsAllowedProxyHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hostname string
		want     bool
	}{
		{"id.vk.ru", true},
		{"api.vk.com", true},
		{"vk.com", true},
		{"sun9-1.userapi.com", true},
		{"ads.vk.com", false},
		{"ads.vk.ru", false},
		{"top-fwz1.mail.ru", false},
		{"sdk-api.apptracer.ru", false},
		{"stats.vk-portal.net", false},
		{"evil.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.hostname, func(t *testing.T) {
			t.Parallel()

			if got := isAllowedProxyHost(tc.hostname); got != tc.want {
				t.Fatalf("isAllowedProxyHost(%q) = %v, want %v", tc.hostname, got, tc.want)
			}
		})
	}
}

func TestLocalExtPathRoundTrip(t *testing.T) {
	t.Parallel()

	src, err := url.Parse("https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/entrypoints/entry.243b7a49.js?v=2")
	if err != nil {
		t.Fatal(err)
	}
	local, err := url.Parse(localExtPath(src))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseLocalExtPath(local.EscapedPath(), local.RawQuery)
	if !ok || got.String() != src.String() {
		t.Fatalf("round trip = %v, %v; want %s", got, ok, src)
	}
}

func TestParseLocalExtPathRejects(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/ext/",
		"/ext/ftp/st.vk.ru/x.js",
		"/ext/https//x.js",
		"/ext/https/evil@st.vk.ru/x.js",
		"/generic_proxy",
	} {
		if u, ok := parseLocalExtPath(path, ""); ok {
			t.Errorf("parseLocalExtPath(%q) = %v, want reject", path, u)
		}
	}
}

// webpack (publicPath auto): адрес скрипта без query и имени файла плюс "../".
func TestWebpackChunksStayOnStaticHost(t *testing.T) {
	t.Parallel()

	page, err := url.Parse("https://id.vk.ru/not_robot_captcha")
	if err != nil {
		t.Fatal(err)
	}
	const entry = "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/entrypoints/entry.243b7a49.js"
	html := rewriteCaptchaHTML(`<head></head><script src="`+entry+`" async></script>`, page)

	m := regexp.MustCompile(`<script src="([^"]+)"`).FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no script src in %q", html)
	}
	scriptURL, err := url.Parse(localCaptchaOrigin())
	if err != nil {
		t.Fatal(err)
	}
	scriptURL, err = scriptURL.Parse(m[1])
	if err != nil {
		t.Fatal(err)
	}

	base := scriptURL.Scheme + "://" + scriptURL.Host + scriptURL.EscapedPath()
	base = base[:strings.LastIndex(base, "/")+1] + "../"
	chunk, err := url.Parse(base + "chunks/js/394.e400a060.js")
	if err != nil {
		t.Fatal(err)
	}
	chunk = chunk.ResolveReference(&url.URL{})

	got, ok := parseLocalExtPath(chunk.EscapedPath(), chunk.RawQuery)
	const want = "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/chunks/js/394.e400a060.js"
	if !ok || got.String() != want {
		t.Fatalf("chunk %s -> %v, %v; want %s", chunk, got, ok, want)
	}
}

func TestRewriteBrowserContext(t *testing.T) {
	t.Parallel()

	page, err := url.Parse("https://id.vk.ru/not_robot_captcha?session_token=x")
	if err != nil {
		t.Fatal(err)
	}
	const css = "http://localhost:8765/ext/https/st.vk.ru/dist/entrypoints/entry.css"

	tests := []struct {
		name                string
		target              string
		origin, referer     string
		wantOrigin, wantRef string
		wantSite            string
	}{
		{
			name:       "api check from page",
			target:     "https://api.vk.ru/method/captchaNotRobot.check",
			origin:     "http://localhost:8765",
			referer:    "http://localhost:8765/not_robot_captcha?session_token=x",
			wantOrigin: "https://id.vk.ru",
			wantRef:    "https://id.vk.ru/",
			wantSite:   "same-site",
		},
		{
			name:     "page navigation",
			target:   "https://id.vk.ru/not_robot_captcha",
			referer:  "http://localhost:8765/not_robot_captcha?session_token=x",
			wantRef:  "https://id.vk.ru/not_robot_captcha?session_token=x",
			wantSite: "same-origin",
		},
		{
			name:     "font from proxied css",
			target:   "https://st.vk.ru/dist/assets/fonts/400cyr.woff2",
			referer:  css,
			wantRef:  "https://st.vk.ru/dist/entrypoints/entry.css",
			wantSite: "same-origin",
		},
		{
			name:     "other vk domain",
			target:   "https://st.vk.com/vkid/vkid-bff/assets/favicon.svg",
			referer:  "http://localhost:8765/not_robot_captcha",
			wantRef:  "https://id.vk.ru/",
			wantSite: "cross-site",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, "http://localhost:8765/", nil) //nolint:noctx // заголовки, сеть не нужна
			if err != nil {
				t.Fatal(err)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			req.Header.Set("Referer", tc.referer)
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			rewriteProxyRequest(req, target, page)

			if got := req.Header.Get("Origin"); got != tc.wantOrigin {
				t.Errorf("Origin = %q, want %q", got, tc.wantOrigin)
			}
			if got := req.Header.Get("Referer"); got != tc.wantRef {
				t.Errorf("Referer = %q, want %q", got, tc.wantRef)
			}
			if got := req.Header.Get("Sec-Fetch-Site"); got != tc.wantSite {
				t.Errorf("Sec-Fetch-Site = %q, want %q", got, tc.wantSite)
			}
		})
	}
}
