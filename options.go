package godns

import (
	"log/slog"
	"time"
)

type Options struct {
	LogLevel string `yaml:"log-level"`
	UDP      string `yaml:"udp"`
	DoH      string `yaml:"doh"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	GeoSite  string `yaml:"geosite"`

	BootstrapDNS []string `yaml:"bootstrap-dns"`

	Cache struct {
		MaxCounters int64         `yaml:"max-counters"`
		MaxCost     int64         `yaml:"max-cost"`
		BufferItems int64         `yaml:"buffer-items"`
		TTL         time.Duration `yaml:"ttl"`
	} `yaml:"cache"`

	Upstream        map[string]string `yaml:"upstream"`
	DefaultUpstream string            `yaml:"default-upstream"`

	Route []string `yaml:"route"`
}

func (o *Options) LoggerLevel() slog.Level {
	switch o.LogLevel {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
