package godns

import (
	"log/slog"

	"github.com/taodev/godns/internal/cache"
	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/transport/http"
	"github.com/taodev/godns/internal/transport/tcp"
	"github.com/taodev/godns/internal/transport/udp"
	"github.com/taodev/pkg/defaults"
)

// 路由配置
type Options struct {
	// 日志级别（debug/info/warn/error）
	LogLevel string `yaml:"log-level" default:"info"`
	// 入站配置
	Inbounds struct {
		// UDP 入站配置
		UDP *udp.Options `yaml:"udp"`
		// TCP 入站配置
		TCP *tcp.Options `yaml:"tcp"`
		// TLS 入站配置
		TLS *tcp.Options `yaml:"tls"`
		// STCP 入站配置
		STCP *tcp.Options `yaml:"stcp"`
		// HTTP 入站配置
		HTTP *http.Options `yaml:"http"`
		// HTTPS 入站配置
		HTTPS *http.Options `yaml:"https"`
	} `yaml:"inbound"`

	// GeoSite 路径
	GeoSite string `yaml:"geosite" default:"geosite.dat"`
	// Bootstrap DNS 服务器
	BootstrapDNS []string `yaml:"bootstrap-dns" default:"[223.5.5.5, 223.6.6.6]"`
	// 缓存配置
	Cache cache.Options `yaml:"cache"`
	// 上游配置
	Outbounds map[string]string `yaml:"outbound"`
	// 路由配置
	Route route.Options `yaml:"route"`
	// 重写配置
	Rewrite rewrite.Options `yaml:"rewrite"`
}

func (o *Options) Default() error {
	return defaults.Set(o)
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
