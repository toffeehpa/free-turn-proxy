package captcha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/toffeehpa/free-turn-proxy/internal/randx"
)

const powResultGlobal = "captchaPowResult"

var (
	rePowArgs   = regexp.MustCompile(`\}\(\s*["']([A-Za-z0-9_-]{8,})["']\s*,\s*(\d+)\s*,\s*["'][^"']*["']\s*(?:,|\)\s*\))`)
	rePowPrefix = regexp.MustCompile(powResultGlobal + `["'\]]{0,3}\s*=\s*["']([A-Za-z0-9._-]{0,8})["']\s*\+`)
	// Четвёртый аргумент - порядок быстрых проб, сервер перемешивает его на каждой странице.
	rePowOrder  = regexp.MustCompile(`\}\(\s*["'][A-Za-z0-9_-]{8,}["']\s*,\s*\d+\s*,\s*["'][^"']*["']\s*,\s*\[([^\]]*)\]`)
	reProbeName = regexp.MustCompile(`["']([a-z0-9_]+)["']`)
)

type powParams struct {
	Input      string
	Difficulty int
	Prefix     string
	Order      []string
}

// powResult - конверт window.captchaPowResult: виджету уходит не голый хэш.
// Порядок полей повторяет порядок ключей у JSON.stringify страницы.
type powResult struct {
	Hash       string          `json:"hash"`
	Nonce      int             `json:"nonce"`
	Error      string          `json:"error"`
	DurationMs int64           `json:"duration_ms"`
	Telemetry  json.RawMessage `json:"telemetry"`
	TelHash    string          `json:"tel_hash"`
}

func parsePowParams(html string) (powParams, error) {
	m := rePowArgs.FindStringSubmatch(html)
	if len(m) < 3 {
		return powParams{}, errors.New("captcha pow args not found")
	}
	difficulty, err := strconv.Atoi(m[2])
	if err != nil || difficulty <= 0 {
		return powParams{}, fmt.Errorf("invalid captcha difficulty %q", m[2])
	}
	prefix := rePowPrefix.FindStringSubmatch(html)
	if len(prefix) < 2 {
		return powParams{}, errors.New("captcha pow envelope not recognized")
	}
	var order []string
	if o := rePowOrder.FindStringSubmatch(html); len(o) > 1 {
		for _, name := range reProbeName.FindAllStringSubmatch(o[1], -1) {
			order = append(order, name[1])
		}
	}
	return powParams{Input: m[1], Difficulty: difficulty, Prefix: prefix[1], Order: order}, nil
}

func (s *captchaSession) powEnvelope(p powParams) (string, error) {
	hash, nonce := solvePoW(s.ctx, p.Input, p.Difficulty)
	if hash == "" {
		return "", errors.New("captcha pow failed")
	}
	probes := s.powTelemetry(p.Order)
	telemetry, err := marshalProbes(probes)
	if err != nil {
		return "", fmt.Errorf("captcha pow telemetry: %w", err)
	}
	telHash, err := telemetryHash(telemetry)
	if err != nil {
		return "", fmt.Errorf("captcha pow tel_hash: %w", err)
	}
	envelope, err := marshalJS(powResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: powDurationMs(probes, nonce),
		Telemetry:  telemetry,
		TelHash:    telHash,
	})
	if err != nil {
		return "", fmt.Errorf("captcha pow encode: %w", err)
	}
	// Печатаем до base64: диффать с живым браузером (см. DecodePowEnvelope) иначе нечем.
	s.logger().Debugf("[Captcha] pow envelope: %s", envelope)
	return p.Prefix + base64.StdEncoding.EncodeToString(envelope), nil
}

// DecodePowEnvelope разворачивает значение window.captchaPowResult обратно в JSON.
func DecodePowEnvelope(value string) string {
	payload := value
	if _, rest, ok := strings.Cut(value, "."); ok {
		payload = rest
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	return string(raw)
}

func solvePoW(ctx context.Context, input string, difficulty int) (string, int) {
	if input == "" || difficulty <= 0 {
		return "", 0
	}
	target := strings.Repeat("0", difficulty)
	buf := make([]byte, 0, len(input)+20)
	buf = append(buf, input...)
	for nonce := 0; nonce <= 10_000_000; nonce++ {
		if nonce&1023 == 0 {
			select {
			case <-ctx.Done():
				return "", 0
			default:
			}
		}
		buf = strconv.AppendInt(buf[:len(input)], int64(nonce), 10)
		sum := sha256.Sum256(buf)
		hashHex := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hashHex, target) {
			return hashHex, nonce
		}
	}
	return "", 0
}

// PoW и пробы идут параллельно, конверт готов, когда закончились оба.
func powDurationMs(probes []namedProbe, nonce int) int64 {
	var probesMs float64
	for _, p := range probes {
		probesMs += p.probe.DurationMs + 0.3
	}
	return max(1, int64(math.Round(max(probesMs, float64(nonce+1)*0.05))))
}

// telemetryHash повторяет канонизатор страницы: ключи по алфавиту (map в Go
// сортирует их сам), undefined на нашей стороне не бывает.
func telemetryHash(telemetry []byte) (string, error) {
	var v any
	if err := json.Unmarshal(telemetry, &v); err != nil {
		return "", err
	}
	canonical, err := marshalJS(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// marshalJS - JSON без HTML-экранирования: JSON.stringify не трогает < > &.
func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// fastProbeOrder - порядок проб самого скрипта, им он добивает список со страницы.
var fastProbeOrder = []string{
	"globals", "ua", "frame", "match_media", "plugins", "nav_tamper", "referrer",
	"css", "native_integrity", "cookie_test", "ancestor_origins", "sandbox_behavior",
	"max_touch_points", "timezone_locale", "device_pixel_ratio", "env_ua",
	"env_viewport", "chrome_runtime", "shadow_dom_check", "ua_high_entropy",
	"origin_via_self", "media_codecs",
}

func probeOrder(page []string) []string {
	out := make([]string, 0, len(fastProbeOrder))
	seen := make(map[string]bool, len(fastProbeOrder))
	known := make(map[string]bool, len(fastProbeOrder))
	for _, name := range fastProbeOrder {
		known[name] = true
	}
	for _, name := range append(page, fastProbeOrder...) {
		if known[name] && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

type powProbe struct {
	OK         bool    `json:"ok"`
	Result     any     `json:"result"`
	DurationMs float64 `json:"duration_ms"`
}

type namedProbe struct {
	name  string
	probe powProbe
}

// Ключи телеметрии идут в порядке проб, как их печатает JSON.stringify страницы.
func marshalProbes(probes []namedProbe) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, p := range probes {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := marshalJS(p.name)
		if err != nil {
			return nil, err
		}
		body, err := marshalJS(p.probe)
		if err != nil {
			return nil, err
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(body)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Почти все пробы - доли миллисекунды, асинхронные и с Intl/CSS дольше.
var probeCostMs = map[string][2]float64{
	"ua_high_entropy":  {0.8, 2.6},
	"timezone_locale":  {0.3, 4},
	"css":              {0.3, 1.3},
	"media_codecs":     {0.3, 1.1},
	"env_viewport":     {0.2, 1.2},
	"env_ua":           {0.2, 0.9},
	"native_integrity": {0.1, 0.6},
	"plugins":          {0.1, 0.5},
}

func probeDurationMs(name string) float64 {
	r, ok := probeCostMs[name]
	if !ok {
		r = [2]float64{0, 0.4}
	}
	return math.Round((r[0]+randx.Float64()*(r[1]-r[0]))*10) / 10
}

type powGlobals struct {
	Doc           bool `json:"doc"`
	Win           bool `json:"win"`
	Nav           bool `json:"nav"`
	Webdriver     bool `json:"webdriver"`
	Subtle        bool `json:"subtle"`
	Secure        bool `json:"secure"`
	GCS           bool `json:"gcs"`
	RAF           bool `json:"raf"`
	Wasm          bool `json:"wasm"`
	PluginsLen    int  `json:"plugins_len"`
	LanguagesLen  int  `json:"languages_len"`
	ChromePresent bool `json:"chromePresent"`
	HW            int  `json:"hw"`
	Mem           *int `json:"mem"`
}

type powUA struct {
	UserAgent     string     `json:"userAgent"`
	UserAgentData *powUAData `json:"userAgentData"`
}

type powUAData struct {
	Brands       []browserprofile.Brand `json:"brands"`
	Platform     string                 `json:"platform"`
	Mobile       bool                   `json:"mobile"`
	Architecture *string                `json:"architecture"`
}

type powFrame struct {
	FrameElement             *string `json:"frameElement"`
	AncestorOriginsLen       int     `json:"ancestorOriginsLen"`
	AncestorOriginsSupported bool    `json:"ancestorOriginsSupported"`
	ParentAccessible         bool    `json:"parentAccessible"`
}

type powMatchMedia struct {
	PrefersDark          bool `json:"prefersDark"`
	PrefersLight         bool `json:"prefersLight"`
	ReducedMotion        bool `json:"reducedMotion"`
	PointerFine          bool `json:"pointerFine"`
	ColorSchemeSupported bool `json:"colorSchemeSupported"`
}

type powPlugins struct {
	Length            int        `json:"length"`
	Names             []string   `json:"names"`
	Descriptions      []string   `json:"descriptions"`
	MimeTypes         [][]string `json:"mimeTypes"`
	IsChrome          bool       `json:"isChrome"`
	PDFViewerEnabled  bool       `json:"pdfViewerEnabled"`
	PluginArrayNative bool       `json:"pluginArrayNative"`
}

type powNavTamper struct {
	Tampered       bool   `json:"tampered"`
	ElCtor         string `json:"el_ctor"`
	StyleCtor      string `json:"style_ctor"`
	NavCtor        string `json:"nav_ctor"`
	AlertNative    bool   `json:"alert_native"`
	ToStringNative bool   `json:"to_string_native"`
}

type powReferrer struct {
	Referrer string `json:"referrer"`
	InIframe bool   `json:"inIframe"`
	Domain   string `json:"domain"`
}

type powCSS struct {
	ExpectedMissing  int   `json:"expectedMissing"`
	EngineFloor      int   `json:"engine_floor"`
	SupportedPerTier []int `json:"supported_per_tier"`
}

type powNativeIntegrity struct {
	ProtoMatch             bool `json:"protoMatch"`
	XHRNative              bool `json:"xhrNative"`
	XHRSendNative          bool `json:"xhrSendNative"`
	AddEventListenerNative bool `json:"addEventListenerNative"`
	AlertNative            bool `json:"alertNative"`
	ToStringNative         bool `json:"toStringNative"`
}

type powCookieTest struct {
	Write bool `json:"write"`
}

type powAncestorOrigins struct {
	AncestorOrigin *string `json:"ancestorOrigin"`
}

type powSandboxBehavior struct {
	OriginIsNull   bool `json:"originIsNull"`
	LocalStorage   bool `json:"localStorage"`
	SessionStorage bool `json:"sessionStorage"`
}

type powMaxTouchPoints struct {
	MaxTouchPoints int `json:"maxTouchPoints"`
}

type powTimezoneLocale struct {
	Timezone  string   `json:"timezone"`
	Languages []string `json:"languages"`
	TZOffset  int      `json:"tz_offset"`
}

type powDevicePixelRatio struct {
	DPR              float64 `json:"dpr"`
	Orientation      string  `json:"orientation"`
	OrientationAngle int     `json:"orientationAngle"`
}

type powEnvUA struct {
	AppVersion   string  `json:"app_version"`
	OSCPU        *string `json:"oscpu"`
	Platform     string  `json:"platform"`
	UAZeroTail   bool    `json:"ua_zero_tail"`
	BrandsUASync bool    `json:"brands_ua_sync"`
	JSHeapGB     float64 `json:"js_heap_gb"`
}

type powEnvViewport struct {
	AvailOK    bool    `json:"avail_ok"`
	VVWidth    int     `json:"vv_width"`
	InnerWidth int     `json:"inner_width"`
	VVScale    float64 `json:"vv_scale"`
	DPRMediaOK bool    `json:"dpr_media_ok"`
}

type powChromeRuntime struct {
	Present bool `json:"present"`
}

type powShadowDOM struct {
	CustomElements bool `json:"customElements"`
	ShadowDOM      bool `json:"shadowDom"`
}

type powHighEntropy struct {
	Platform        *string                `json:"platform"`
	PlatformVersion *string                `json:"platformVersion"`
	Architecture    *string                `json:"architecture"`
	Model           *string                `json:"model"`
	UAFullVersion   *string                `json:"uaFullVersion"`
	FullVersionList []browserprofile.Brand `json:"fullVersionList"`
	Bitness         *string                `json:"bitness"`
	FormFactors     []string               `json:"formFactors"`
	Wow64           bool                   `json:"wow64"`
}

type powOrigin struct {
	Origin       string `json:"origin"`
	OriginIsNull bool   `json:"originIsNull"`
}

type powMediaCodecs struct {
	H264    int `json:"h264"`
	AVCHigh int `json:"avc_high"`
	HVC     int `json:"hvc"`
	VP9     int `json:"vp9"`
	VP8     int `json:"vp8"`
	Theora  int `json:"theora"`
	MP4A    int `json:"mp4a"`
	AAC     int `json:"aac"`
	M4A     int `json:"m4a"`
	MP3     int `json:"mp3"`
	MSEH264 int `json:"mse_h264"`
	MSEVP9  int `json:"mse_vp9"`
}

var chromePDFPlugins = []string{
	"PDF Viewer",
	"Chrome PDF Viewer",
	"Chromium PDF Viewer",
	"Microsoft Edge PDF Viewer",
	"WebKit built-in PDF",
}

const chromePDFDescription = "Portable Document Format"

// У Plugin нет свойства mimeTypes, скрипт видит пустой список на каждый плагин.
func chromePlugins() powPlugins {
	out := powPlugins{
		Length:            len(chromePDFPlugins),
		Names:             chromePDFPlugins,
		Descriptions:      make([]string, len(chromePDFPlugins)),
		MimeTypes:         make([][]string, len(chromePDFPlugins)),
		IsChrome:          true,
		PDFViewerEnabled:  true,
		PluginArrayNative: true,
	}
	for i := range chromePDFPlugins {
		out.Descriptions[i] = chromePDFDescription
		out.MimeTypes[i] = []string{}
	}
	return out
}

// Chrome 123+ проходит всю лесенку CSS-фич скрипта.
const (
	cssEngineFloor  = 123
	cssTiers        = 10
	tzOffsetMoscow  = -180
	jsHeapGBDesktop = 4.09
	jsHeapGBMobile  = 1.06
)

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// powTelemetry описывает страницу такой, какой её видел бы браузер персоны:
// страницу мы тянем верхнеуровневой навигацией (Sec-Fetch-Dest: document),
// поэтому frame и referrer описывают top-level документ - врозь их менять нельзя.
func (s *captchaSession) powTelemetry(pageOrder []string) []namedProbe {
	results := s.probeResults()
	cost := s.probeMs
	if cost == nil {
		cost = probeDurationMs
	}
	order := probeOrder(pageOrder)
	out := make([]namedProbe, 0, len(order))
	for _, name := range order {
		out = append(out, namedProbe{name: name, probe: powProbe{
			OK: true, Result: results[name], DurationMs: cost(name),
		}})
	}
	return out
}

func (s *captchaSession) probeResults() map[string]any {
	p := s.profile
	mobile := p.IsMobile()
	// На Android нет встроенного PDF-вьювера, значит и списка плагинов.
	plugins := powPlugins{Names: []string{}, Descriptions: []string{}, MimeTypes: [][]string{}, PluginArrayNative: true}
	heapGB := jsHeapGBMobile
	if !mobile {
		plugins = chromePlugins()
		heapGB = jsHeapGBDesktop
	}
	tiers := make([]int, cssTiers)
	for i := range tiers {
		tiers[i] = 1
	}
	he := p.HighEntropy()
	dark := prefersDark(p)
	return map[string]any{
		"globals": powGlobals{
			Doc: true, Win: true, Nav: true,
			Webdriver:     p.Webdriver(),
			Subtle:        true,
			Secure:        true,
			GCS:           true,
			RAF:           true,
			Wasm:          true,
			PluginsLen:    plugins.Length,
			LanguagesLen:  len(p.Languages()),
			ChromePresent: true,
			HW:            p.HardwareConcurrency(),
			Mem:           p.DeviceMemory(),
		},
		"ua": powUA{
			UserAgent: p.UserAgent,
			UserAgentData: &powUAData{
				Brands:   p.Brands(),
				Platform: p.PlatformName(),
				Mobile:   mobile,
			},
		},
		"frame":       powFrame{AncestorOriginsSupported: true, ParentAccessible: true},
		"match_media": powMatchMedia{PrefersDark: dark, PrefersLight: !dark, PointerFine: !mobile, ColorSchemeSupported: true},
		"plugins":     plugins,
		"nav_tamper": powNavTamper{
			ElCtor: "HTMLDivElement", StyleCtor: "CSSStyleDeclaration", NavCtor: "Navigator",
			AlertNative: true, ToStringNative: true,
		},
		"referrer": powReferrer{
			Referrer: "https://" + s.domain + "/",
			Domain:   strings.TrimPrefix(s.pageOrigin, "https://"),
		},
		"css": powCSS{EngineFloor: cssEngineFloor, SupportedPerTier: tiers},
		"native_integrity": powNativeIntegrity{
			ProtoMatch: true, XHRNative: true, XHRSendNative: true,
			AddEventListenerNative: true, AlertNative: true, ToStringNative: true,
		},
		"cookie_test":      powCookieTest{Write: true},
		"ancestor_origins": powAncestorOrigins{},
		"sandbox_behavior": powSandboxBehavior{LocalStorage: true, SessionStorage: true},
		"max_touch_points": powMaxTouchPoints{MaxTouchPoints: p.MaxTouchPoints()},
		"timezone_locale":  powTimezoneLocale{Timezone: p.Timezone(), Languages: p.Languages(), TZOffset: tzOffsetMoscow},
		"device_pixel_ratio": powDevicePixelRatio{
			DPR:         p.DevicePixelRatio(),
			Orientation: p.Orientation(),
		},
		"env_ua": powEnvUA{
			AppVersion:   strings.TrimPrefix(p.UserAgent, "Mozilla/"),
			Platform:     p.NavigatorPlatform(),
			UAZeroTail:   true,
			BrandsUASync: true,
			JSHeapGB:     heapGB,
		},
		"env_viewport": powEnvViewport{
			AvailOK: true, VVWidth: p.InnerWidth(), InnerWidth: p.InnerWidth(), VVScale: 1, DPRMediaOK: true,
		},
		"chrome_runtime":   powChromeRuntime{},
		"shadow_dom_check": powShadowDOM{CustomElements: true, ShadowDOM: true},
		"ua_high_entropy": powHighEntropy{
			Platform:        nullable(he.Platform),
			PlatformVersion: nullable(he.PlatformVersion),
			Architecture:    nullable(he.Architecture),
			Model:           nullable(he.Model),
			UAFullVersion:   nullable(he.UAFullVersion),
			FullVersionList: he.FullVersionList,
			Bitness:         nullable(he.Bitness),
			FormFactors:     he.FormFactors,
		},
		"origin_via_self": powOrigin{Origin: s.pageOrigin},
		"media_codecs": powMediaCodecs{
			H264: 2, AVCHigh: 2, HVC: 2, VP9: 2, VP8: 2,
			MP4A: 2, AAC: 2, M4A: 1, MP3: 2, MSEH264: 1, MSEVP9: 1,
		},
	}
}

// prefers-color-scheme у живого посетителя не скачет между сессиями - берём бит персоны.
func prefersDark(p browserprofile.Profile) bool {
	return len(p.VisitorID) > 0 && p.VisitorID[0]%2 == 1
}
