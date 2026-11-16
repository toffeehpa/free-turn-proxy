package captcha

import (
	"testing"
	"time"
)

// Эталон снят с успешного check живого браузера через manual-прокси.
func TestAnalyticsMatchesLiveBrowser(t *testing.T) {
	want := [][2]string{
		{"accelerometer", "[]"},
		{"gyroscope", "[]"},
		{"motion", "[]"},
		{"cursor", "[]"},
		{"taps", "[]"},
	}
	got := analyticsFields()

	if len(got) != len(want) {
		t.Fatalf("%d fields, want %d", len(got), len(want))
	}
	for i, kv := range got {
		if kv != want[i] {
			t.Fatalf("field %d = %v, want %v", i, kv, want[i])
		}
	}
}

func TestParseSensorConfigFallsBackToDefaults(t *testing.T) {
	cfg := parseSensorConfig(map[string]any{"error": map[string]any{"error_code": float64(5)}})
	if cfg != defaultSensorConfig() {
		t.Fatalf("sensor config = %+v, want defaults", cfg)
	}
	clamped := parseSensorConfig(map[string]any{"response": map[string]any{"sensors_delay": float64(1)}})
	if clamped.delay != sensorDelayFloor {
		t.Fatalf("delay = %s, want clamp to %s", clamped.delay, sensorDelayFloor)
	}
}

func TestParseSensorConfigReadsDelay(t *testing.T) {
	cfg := parseSensorConfig(map[string]any{"response": map[string]any{"sensors_delay": float64(250)}})
	if cfg.delay != 250*time.Millisecond {
		t.Fatalf("delay = %s, want 250ms", cfg.delay)
	}
}
