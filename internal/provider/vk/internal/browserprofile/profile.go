package browserprofile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	chromeSecChUa = `"Google Chrome";v="146", "Chromium";v="146", "Not)A;Brand";v="24"`

	uaWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	uaMac     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	uaAndroid = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

	chromeFullVersion = "146.0.7680.164"

	timezoneMoscow    = "Europe/Moscow"
	touchPointsMobile = 5
)

type Platform string

const (
	Desktop Platform = "desktop"
	Mobile  Platform = "mobile"
)

// PlatformFromString преобразует строку в Platform (по умолчанию Desktop).
func PlatformFromString(s string) Platform {
	if s == string(Mobile) {
		return Mobile
	}
	return Desktop
}

// Profile содержит браузерные параметры и отпечатки (UA, client hints, device fingerprint).
type Profile struct {
	Platform        Platform
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string
	DeviceJSON      string
	VisitorID       string

	cores     int
	memGB     int
	webdriver bool
	dev       device
	hints     hints
}

func (p Profile) IsMobile() bool { return p.Platform == Mobile }

func (p Profile) HardwareConcurrency() int { return p.cores }

func (p Profile) Webdriver() bool { return p.webdriver }

func (p Profile) DeviceMemory() *int {
	if p.memGB == 0 {
		return nil
	}
	return &p.memGB
}

func (p Profile) Languages() []string { return p.dev.Languages }

func (p Profile) DevicePixelRatio() float64 { return p.dev.DevicePixelRatio }

func (Profile) Timezone() string { return timezoneMoscow }

func (p Profile) MaxTouchPoints() int {
	if p.IsMobile() {
		return touchPointsMobile
	}
	return 0
}

func (p Profile) Orientation() string {
	if p.IsMobile() {
		return "portrait-primary"
	}
	return "landscape-primary"
}

func (p Profile) PlatformName() string { return strings.Trim(p.SecChUaPlatform, `"`) }

func (p Profile) NavigatorPlatform() string { return p.hints.navPlatform }

func (p Profile) InnerWidth() int { return p.dev.InnerWidth }

type HighEntropy struct {
	Platform        string
	PlatformVersion string
	Architecture    string
	Model           string
	UAFullVersion   string
	FullVersionList []Brand
	Bitness         string
	FormFactors     []string
}

func (p Profile) HighEntropy() HighEntropy {
	full := make([]Brand, 0, 3)
	for _, b := range p.Brands() {
		v := chromeFullVersion
		if !strings.Contains(b.Brand, "Chrom") {
			v = b.Version + ".0.0.0"
		}
		full = append(full, Brand{Brand: b.Brand, Version: v})
	}
	formFactor := "Desktop"
	if p.IsMobile() {
		formFactor = "Mobile"
	}
	return HighEntropy{
		Platform:        p.PlatformName(),
		PlatformVersion: p.hints.platformVersion,
		Architecture:    p.hints.arch,
		Model:           p.hints.model,
		UAFullVersion:   chromeFullVersion,
		FullVersionList: full,
		Bitness:         p.hints.bitness,
		FormFactors:     []string{formFactor},
	}
}

type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

func (p Profile) Brands() []Brand {
	out := make([]Brand, 0, 3)
	for _, part := range strings.Split(p.SecChUa, ", ") {
		name, ver, ok := strings.Cut(part, ";v=")
		if !ok {
			continue
		}
		out = append(out, Brand{Brand: strings.Trim(name, `"`), Version: strings.Trim(ver, `"`)})
	}
	return out
}

type device struct {
	ScreenWidth             int      `json:"screenWidth"`
	ScreenHeight            int      `json:"screenHeight"`
	ScreenAvailWidth        int      `json:"screenAvailWidth"`
	ScreenAvailHeight       int      `json:"screenAvailHeight"`
	InnerWidth              int      `json:"innerWidth"`
	InnerHeight             int      `json:"innerHeight"`
	DevicePixelRatio        float64  `json:"devicePixelRatio"`
	Language                string   `json:"language"`
	Languages               []string `json:"languages"`
	Webdriver               bool     `json:"webdriver"`
	HardwareConcurrency     int      `json:"hardwareConcurrency"`
	DeviceMemory            *int     `json:"deviceMemory,omitempty"`
	ConnectionEffectiveType string   `json:"connectionEffectiveType,omitempty"`
	NotificationsPermission string   `json:"notificationsPermission"`
}

var chromeHeaderOrder = []string{
	"content-length",
	"sec-ch-ua-platform",
	"user-agent",
	"sec-ch-ua",
	"content-type",
	"sec-ch-ua-mobile",
	"upgrade-insecure-requests",
	"accept",
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
	"priority",
}

type spec struct {
	userAgent  string
	chPlatform string
	dev        device
	hints      hints
}

type hints struct {
	navPlatform     string
	platformVersion string
	arch            string
	bitness         string
	model           string
}

var (
	hintsWindows = hints{navPlatform: "Win32", platformVersion: "19.0.0", arch: "x86", bitness: "64"}
	hintsMac     = hints{navPlatform: "MacIntel", platformVersion: "15.6.1", arch: "arm", bitness: "64"}
)

// На Android архитектуру и разрядность Chrome не отдаёт, зато отдаёт модель.
func hintsAndroid(platformVersion, model string) hints {
	return hints{navPlatform: "Linux armv81", platformVersion: platformVersion, model: model}
}

var desktopSpecs = []spec{
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newDevice(1920, 1080, 1032, 1147, 945, 1, 16, 8), hints: hintsWindows},
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newDevice(1536, 864, 816, 1229, 738, 1.25, 8, 8), hints: hintsWindows},
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newDevice(2560, 1440, 1392, 1512, 1237, 1, 12, 8), hints: hintsWindows},
	{userAgent: uaMac, chPlatform: `"macOS"`, dev: newDevice(1512, 982, 944, 1147, 870, 2, 10, 8), hints: hintsMac},
}

var mobileSpecs = []spec{
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newDevice(364, 793, 793, 363, 671, 3.5, 8, 8), hints: hintsAndroid("14.0.0", "SM-S911B")},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newDevice(393, 852, 852, 393, 659, 3, 8, 8), hints: hintsAndroid("14.0.0", "SM-A546B")},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newDevice(412, 915, 915, 412, 724, 2.625, 8, 4), hints: hintsAndroid("15.0.0", "Pixel 7")},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newDevice(360, 800, 800, 360, 612, 3, 8, 4), hints: hintsAndroid("13.0.0", "SM-A525F")},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newDevice(384, 832, 832, 384, 644, 2.75, 8, 8), hints: hintsAndroid("13.0.0", "2201117TG")},
}

// Identity идентифицирует браузерную личность и её поколение.
type Identity struct {
	Seed string
	Gen  int
}

func (id Identity) String() string { return id.Seed + "|" + strconv.Itoa(id.Gen) }

// For генерирует профиль браузера для указанной платформы и идентичности.
func For(p Platform, id Identity) Profile {
	specs := desktopSpecs
	if p == Mobile {
		specs = mobileSpecs
	} else {
		p = Desktop
	}

	sum := sha256.Sum256([]byte(id.String()))
	s := specs[binary.BigEndian.Uint64(sum[:8])%uint64(len(specs))]

	profile := Profile{
		Platform:        p,
		SecChUa:         chromeSecChUa,
		SecChUaMobile:   "?0",
		SecChUaPlatform: s.chPlatform,
		AcceptLanguage:  "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		UserAgent:       s.userAgent,
	}
	if p == Mobile {
		profile.SecChUaMobile = "?1"
	}

	profile = withDevice(profile, s.dev)
	profile.hints = s.hints
	profile.VisitorID = visitorID(id, profile)
	return profile
}

func newDevice(screenW, screenH, availH, innerW, innerH int, dpr float64, cores, memGB int) device {
	memory := memGB
	return device{
		ScreenWidth: screenW, ScreenHeight: screenH,
		ScreenAvailWidth: screenW, ScreenAvailHeight: availH,
		InnerWidth: innerW, InnerHeight: innerH,
		DevicePixelRatio:        dpr,
		Language:                "ru-RU",
		Languages:               []string{"ru-RU", "en-US"},
		HardwareConcurrency:     cores,
		DeviceMemory:            &memory,
		ConnectionEffectiveType: "4g",
		NotificationsPermission: "denied",
	}
}

func visitorID(id Identity, p Profile) string {
	sum := sha256.Sum256([]byte(id.String() + "|" + p.UserAgent + "|" + p.DeviceJSON))
	return hex.EncodeToString(sum[:16])
}

func withDevice(p Profile, d device) Profile {
	data, err := json.Marshal(d)
	if err != nil {
		return p
	}
	p.DeviceJSON = string(data)
	p.dev = d
	p.cores, p.webdriver = d.HardwareConcurrency, d.Webdriver
	if d.DeviceMemory != nil {
		p.memGB = *d.DeviceMemory
	}
	return p
}

func (Profile) ClientProfile() profiles.ClientProfile {
	return profiles.Chrome_146
}

func ApplyFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	if req.Header.Get("Sec-Fetch-Dest") == "document" {
		req.Header.Set("Priority", "u=0, i")
	} else {
		req.Header.Set("Priority", "u=1, i")
	}
	req.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder
}

func ApplyProxyFhttp(req *fhttp.Request) {
	req.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder
}
