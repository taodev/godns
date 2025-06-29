package godns

import "log/slog"

type Options struct {
	LogLevel string `yaml:"log-level"`
	UDP      string `yaml:"udp"`
	DoH      string `yaml:"doh"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	GeoSite  string `yaml:"geosite"`

	BootstrapDNS []string `yaml:"bootstrap-dns"`

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
