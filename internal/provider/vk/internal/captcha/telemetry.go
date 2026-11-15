package captcha

import (
	"time"
)

const (
	sensorDelayDefault = 100 * time.Millisecond
	sensorDelayFloor   = 20 * time.Millisecond
	sensorDelayCeil    = 2 * time.Second
	emptyArray         = "[]"
)

// sensorConfig - период таймера телеметрии; приходит из captchaNotRobot.settings.
type sensorConfig struct {
	delay time.Duration
}

func defaultSensorConfig() sensorConfig {
	return sensorConfig{delay: sensorDelayDefault}
}

func parseSensorConfig(raw map[string]any) sensorConfig {
	cfg := defaultSensorConfig()
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return cfg
	}
	if ms, hasDelay := resp["sensors_delay"].(float64); hasDelay && ms > 0 {
		cfg.delay = min(max(time.Duration(ms)*time.Millisecond, sensorDelayFloor), sensorDelayCeil)
	}
	return cfg
}

// analyticsFields - аккумулятор виджета в порядке его ключей; без датчиков и
// курсора массивы пустые.
func analyticsFields() [][2]string {
	return [][2]string{
		{"accelerometer", emptyArray},
		{"gyroscope", emptyArray},
		{"motion", emptyArray},
		{"cursor", emptyArray},
		{"taps", emptyArray},
	}
}
