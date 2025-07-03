package godns

import (
	"log/slog"

	"github.com/taodev/godns/internal/cache"
	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/transport/tcp"
	"github.com/taodev/pkg/defaults"
)

// 路由配置
type Options struct {
	// 日志级别（debug/info/warn/error）
	LogLevel string `yaml:"log-level" default:"info"`

	// 入站配置
	Inbounds struct {
		// TCP 入站配置
		TCP *tcp.Options `yaml:"tcp"`
		// TLS 入站配置
		TLS *tcp.Options `yaml:"tls"`
		// STCP 入站配置
		STCP *tcp.Options `yaml:"stcp"`
	} `yaml:"inbound"`

	// HTTPS 证书路径（可选，启用 TLS）
	Cert string `yaml:"cert"`
	// HTTPS 私钥路径（可选）
	Key string `yaml:"key"`
	// GeoSite 路径
	GeoSite string `yaml:"geosite" default:"geosite.dat"`
	// 是否阻止 AAAA 查询（IPv6）
	BlockAAAA bool `yaml:"block-aaaa"`
	// Bootstrap DNS 服务器
	BootstrapDNS []string `yaml:"bootstrap-dns" default:"[223.5.5.5, 223.6.6.6]"`

	// 缓存配置
	Cache cache.Options `yaml:"cache"`

	// 上游配置
	Upstream  map[string]string `yaml:"upstream"`
	Outbounds map[string]string `yaml:"outbound"`
	// 默认上游（未配置时使用第一个）
	DefaultUpstream string `yaml:"default-upstream"`

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
