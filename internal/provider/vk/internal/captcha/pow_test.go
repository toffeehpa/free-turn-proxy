package captcha

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/toffeehpa/free-turn-proxy/internal/provider/vk/internal/browserprofile"
)

// Живая страница captcha, снятая целиком: PoW-скрипт обфусцирован, поэтому
// контракт проверяется на настоящей разметке, а не на её пересказе. Обновлять
// фикстуру - task captcha:page.
func TestParseCaptchaPageFixture(t *testing.T) {
	html, err := os.ReadFile("testdata/not_robot_captcha.html")
	if err != nil {
		t.Fatal(err)
	}

	page, err := parseCaptchaPage(string(html))
	if err != nil {
		t.Fatal(err)
	}
	if page.Pow.Input != "HPVavCjg6NV62g46" || page.Pow.Difficulty != 2 || page.Pow.Prefix != "v2." {
		t.Fatalf("pow = %+v", page.Pow)
	}
	if len(page.Pow.Order) != len(fastProbeOrder) || page.Pow.Order[0] != "shadow_dom_check" || page.Pow.Order[21] != "referrer" {
		t.Fatalf("pow order = %v", page.Pow.Order)
	}
	if page.DebugInfo != "8275c271-01e7-4bac-a4f1-0c25c3996819" {
		t.Fatalf("debug_info = %q", page.DebugInfo)
	}
	if page.Init.Found {
		t.Fatalf("init = %+v", page.Init)
	}
}

// Незнакомая разметка обязана ронять авторешение, а не уезжать в check заведомо
// неверным hash.
func TestParsePowParamsRejectsUnknownMarkup(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{name: "no pow script", html: `<html><body><div id="spa_root"></div></body></html>`},
		{
			name: "args without envelope",
			html: `<script>(function(a,b,c){})("fnZQN7lKKXvo37tH",2,"pow_timeout"));</script>`,
		},
		{
			name: "envelope without args",
			html: `<script>window['captchaPowResult']='v2.'+btoa(x);}(powInput,difficulty,"pow_timeout"));</script>`,
		},
		{
			name: "zero difficulty",
			html: `<script>window['captchaPowResult']='v2.'+btoa(x);}("fnZQN7lKKXvo37tH",0,"pow_timeout"));</script>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePowParams(tt.html); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePowParamsAcceptsAdditionalArgs(t *testing.T) {
	html := `<script>window['captchaPowResult']='v2.'+btoa(x);}('fnZQN7lKKXvo37tH',2,'pow_timeout',["globals"]));</script>`

	got, err := parsePowParams(html)
	if err != nil {
		t.Fatal(err)
	}
	if got.Input != "fnZQN7lKKXvo37tH" || got.Difficulty != 2 || got.Prefix != "v2." || len(got.Order) != 1 || got.Order[0] != "globals" {
		t.Fatalf("pow = %+v", got)
	}
}

// Скрипт берёт известные пробы со страницы без повторов и добивает недостающие
// из своего списка.
func TestProbeOrder(t *testing.T) {
	got := probeOrder([]string{"css", "unknown", "globals", "css"})
	if len(got) != len(fastProbeOrder) || got[0] != "css" || got[1] != "globals" || got[2] != "ua" {
		t.Fatalf("order = %v", got)
	}
}

func TestSolvePoW(t *testing.T) {
	got, nonce := solvePoW(context.Background(), "input", 1)
	if len(got) != 64 || !strings.HasPrefix(got, "0") {
		t.Fatalf("pow = %q, want 64-hex with leading zero", got)
	}
	sum := sha256.Sum256([]byte("input" + strconv.Itoa(nonce)))
	if hex.EncodeToString(sum[:]) != got {
		t.Fatalf("pow hash does not match sha256(input+nonce)")
	}
}

// Эталон снят с персоны seed=fixture при пробах по 0.1 мс; схема проб сверена
// с конвертом живого Chrome, tel_hash - с канонизатором самой страницы. Любая
// правка значений телеметрии обязана осознанно двигать эталон.
const (
	goldenTelemetry = `{"globals":{"ok":true,"result":{"doc":true,"win":true,"nav":true,"webdriver":false,"subtle":true,"secure":true,"gcs":true,"raf":true,"wasm":true,"plugins_len":5,"languages_len":2,"chromePresent":true,"hw":12,"mem":8},"duration_ms":0.1},` +
		`"ua":{"ok":true,"result":{"userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36","userAgentData":{"brands":[{"brand":"Google Chrome","version":"146"},{"brand":"Chromium","version":"146"},{"brand":"Not)A;Brand","version":"24"}],"platform":"Windows","mobile":false,"architecture":null}},"duration_ms":0.1},` +
		`"frame":{"ok":true,"result":{"frameElement":null,"ancestorOriginsLen":0,"ancestorOriginsSupported":true,"parentAccessible":true},"duration_ms":0.1},` +
		`"match_media":{"ok":true,"result":{"prefersDark":true,"prefersLight":false,"reducedMotion":false,"pointerFine":true,"colorSchemeSupported":true},"duration_ms":0.1},` +
		`"plugins":{"ok":true,"result":{"length":5,"names":["PDF Viewer","Chrome PDF Viewer","Chromium PDF Viewer","Microsoft Edge PDF Viewer","WebKit built-in PDF"],"descriptions":["Portable Document Format","Portable Document Format","Portable Document Format","Portable Document Format","Portable Document Format"],"mimeTypes":[[],[],[],[],[]],"isChrome":true,"pdfViewerEnabled":true,"pluginArrayNative":true},"duration_ms":0.1},` +
		`"nav_tamper":{"ok":true,"result":{"tampered":false,"el_ctor":"HTMLDivElement","style_ctor":"CSSStyleDeclaration","nav_ctor":"Navigator","alert_native":true,"to_string_native":true},"duration_ms":0.1},` +
		`"referrer":{"ok":true,"result":{"referrer":"https://vk.com/","inIframe":false,"domain":"id.vk.ru"},"duration_ms":0.1},` +
		`"css":{"ok":true,"result":{"expectedMissing":0,"engine_floor":123,"supported_per_tier":[1,1,1,1,1,1,1,1,1,1]},"duration_ms":0.1},` +
		`"native_integrity":{"ok":true,"result":{"protoMatch":true,"xhrNative":true,"xhrSendNative":true,"addEventListenerNative":true,"alertNative":true,"toStringNative":true},"duration_ms":0.1},` +
		`"cookie_test":{"ok":true,"result":{"write":true},"duration_ms":0.1},` +
		`"ancestor_origins":{"ok":true,"result":{"ancestorOrigin":null},"duration_ms":0.1},` +
		`"sandbox_behavior":{"ok":true,"result":{"originIsNull":false,"localStorage":true,"sessionStorage":true},"duration_ms":0.1},` +
		`"max_touch_points":{"ok":true,"result":{"maxTouchPoints":0},"duration_ms":0.1},` +
		`"timezone_locale":{"ok":true,"result":{"timezone":"Europe/Moscow","languages":["ru-RU","en-US"],"tz_offset":-180},"duration_ms":0.1},` +
		`"device_pixel_ratio":{"ok":true,"result":{"dpr":1,"orientation":"landscape-primary","orientationAngle":0},"duration_ms":0.1},` +
		`"env_ua":{"ok":true,"result":{"app_version":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36","oscpu":null,"platform":"Win32","ua_zero_tail":true,"brands_ua_sync":true,"js_heap_gb":4.09},"duration_ms":0.1},` +
		`"env_viewport":{"ok":true,"result":{"avail_ok":true,"vv_width":1512,"inner_width":1512,"vv_scale":1,"dpr_media_ok":true},"duration_ms":0.1},` +
		`"chrome_runtime":{"ok":true,"result":{"present":false},"duration_ms":0.1},` +
		`"shadow_dom_check":{"ok":true,"result":{"customElements":true,"shadowDom":true},"duration_ms":0.1},` +
		`"ua_high_entropy":{"ok":true,"result":{"platform":"Windows","platformVersion":"19.0.0","architecture":"x86","model":null,"uaFullVersion":"146.0.7680.164","fullVersionList":[{"brand":"Google Chrome","version":"146.0.7680.164"},{"brand":"Chromium","version":"146.0.7680.164"},{"brand":"Not)A;Brand","version":"24.0.0.0"}],"bitness":"64","formFactors":["Desktop"],"wow64":false},"duration_ms":0.1},` +
		`"origin_via_self":{"ok":true,"result":{"origin":"https://id.vk.ru","originIsNull":false},"duration_ms":0.1},` +
		`"media_codecs":{"ok":true,"result":{"h264":2,"avc_high":2,"hvc":2,"vp9":2,"vp8":2,"theora":0,"mp4a":2,"aac":2,"m4a":1,"mp3":2,"mse_h264":1,"mse_vp9":1},"duration_ms":0.1}}`

	goldenTelHash = "078624ec55c98912ea1e8a4f5f0294ce1bfb3232131cefcc26e702463d4ccb43"
)

// Конверт целиком: порядок ключей, телеметрия персоны и её sha256 - всё, что VK
// проверяет на check.
func TestPowEnvelope(t *testing.T) {
	s := &captchaSession{
		ctx:        context.Background(),
		profile:    browserprofile.For(browserprofile.Desktop, browserprofile.Identity{Seed: "fixture"}),
		domain:     "vk.com",
		pageOrigin: "https://id.vk.ru",
		probeMs:    func(string) float64 { return 0.1 },
	}

	got, err := s.powEnvelope(powParams{Input: "input", Difficulty: 1, Prefix: "v2."})
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := strings.CutPrefix(got, "v2.")
	if !ok {
		t.Fatalf("envelope = %q, want v2. prefix", got)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}

	hash, nonce := solvePoW(context.Background(), "input", 1)
	want := `{"hash":"` + hash + `","nonce":` + strconv.Itoa(nonce) +
		`,"error":"","duration_ms":9` +
		`,"telemetry":` + goldenTelemetry + `,"tel_hash":"` + goldenTelHash + `"}`
	if string(raw) != want {
		t.Fatalf("envelope =\n%s\nwant\n%s", raw, want)
	}
}

// Android Chrome без PDF-вьювера: плагинов нет, а navigator.platform и client
// hints - телефонные.
func TestPowTelemetryMobile(t *testing.T) {
	s := &captchaSession{
		ctx:        context.Background(),
		profile:    browserprofile.For(browserprofile.Mobile, browserprofile.Identity{Seed: "fixture"}),
		domain:     "vk.com",
		pageOrigin: "https://id.vk.ru",
	}
	results := s.probeResults()

	plugins, ok := results["plugins"].(powPlugins)
	if !ok || plugins.Length != 0 || plugins.PDFViewerEnabled || !plugins.PluginArrayNative {
		t.Fatalf("plugins = %+v", results["plugins"])
	}
	env, ok := results["env_ua"].(powEnvUA)
	if !ok || env.Platform != "Linux armv81" {
		t.Fatalf("env_ua = %+v", results["env_ua"])
	}
	he, ok := results["ua_high_entropy"].(powHighEntropy)
	if !ok || he.Architecture != nil || he.Bitness != nil || he.Model == nil || he.FormFactors[0] != "Mobile" {
		t.Fatalf("ua_high_entropy = %+v", results["ua_high_entropy"])
	}
}

func TestTelemetryHashCanonicalizesKeys(t *testing.T) {
	// Тот же объект с переставленными ключами обязан дать тот же tel_hash.
	shuffled := `{"b":{"y":1,"x":[2,{"n":null,"m":"s"}]},"a":true}`
	ordered := `{"a":true,"b":{"x":[2,{"m":"s","n":null}],"y":1}}`

	first, err := telemetryHash([]byte(shuffled))
	if err != nil {
		t.Fatal(err)
	}
	second, err := telemetryHash([]byte(ordered))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("tel_hash = %s vs %s", first, second)
	}
	sum := sha256.Sum256([]byte(ordered))
	if first != hex.EncodeToString(sum[:]) {
		t.Fatalf("tel_hash = %s, want sha256 of canonical form", first)
	}
}
