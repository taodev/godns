package godns

import (
	"log/slog"
	"time"
)

type RewriteOptions struct {
	Domain string        `yaml:"domain"`
	Type   string        `yaml:"type"`
	Value  string        `yaml:"value"`
	TTL    time.Duration `yaml:"ttl"`
}

type Options struct {
	LogLevel string `yaml:"log-level"`
	UDP      string `yaml:"udp"`
	TCP      string `yaml:"tcp"`

	STCP struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
	} `yaml:"stcp"`

	DoH     string `yaml:"doh"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
	GeoSite string `yaml:"geosite"`
	// 是否阻止 AAAA 查询（IPv6）
	BlockAAAA bool `yaml:"block-aaaa"`

	BootstrapDNS []string `yaml:"bootstrap-dns"`

	Cache struct {
		MaxCounters int64         `yaml:"max-counters"`
		MaxCost     int64         `yaml:"max-cost"`
		BufferItems int64         `yaml:"buffer-items"`
		TTL         time.Duration `yaml:"ttl"`
		MinTTL      time.Duration `yaml:"min-ttl"` // 覆盖最小 TTL 值
		MaxTTL      time.Duration `yaml:"max-ttl"` // 覆盖最大 TTL
	} `yaml:"cache"`

	Upstream        map[string]string `yaml:"upstream"`
	DefaultUpstream string            `yaml:"default-upstream"`

	Route   []string         `yaml:"route"`
	Rewrite []RewriteOptions `yaml:"rewrite"`
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
