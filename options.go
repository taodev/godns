package godns

import (
	"log/slog"
	"time"

	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/transport/tcp"
	"github.com/taodev/pkg/defaults"
)

// 重写配置
type RewriteOptions struct {
	// 域名
	Domain string `yaml:"domain"`
	// 类型
	Type string `yaml:"type" default:"A"`
	// 值
	Value string `yaml:"value"`
	// TTL
	TTL time.Duration `yaml:"ttl" default:"60s"`
}

// 路由配置
type Options struct {
	// 日志级别（debug/info/warn/error）
	LogLevel string `yaml:"log-level" default:"info"`
	// UDP 服务监听地址
	UDP string `yaml:"udp"`

	// 入站配置
	Inbounds struct {
		// TCP 入站配置
		TCP *tcp.Options `yaml:"tcp"`
		// TLS 入站配置
		TLS *tcp.Options `yaml:"tls"`
		// STCP 入站配置
		STCP *tcp.Options `yaml:"stcp"`
	} `yaml:"inbound"`

	// DoH 服务监听地址
	DoH string `yaml:"doh"`
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
	Cache struct {
		// 最大缓存条目数
		MaxCounters int64 `yaml:"max-counters" default:"10000"`
		// 最大缓存成本（与条目大小相关）
		MaxCost int64 `yaml:"max-cost" default:"10000"`
		// 写缓存数量
		BufferItems int64 `yaml:"buffer-items" default:"64"`
		// 缓存默认 TTL
		TTL time.Duration `yaml:"ttl" default:"24h"`
		// 最小覆盖 TTL (format: 1h, 1m, 1s)
		MinTTL time.Duration `yaml:"min-ttl" default:"60s"` // 覆盖最小 TTL 值
		// 最大覆盖 TTL (format: 1h, 1m, 1s)
		MaxTTL time.Duration `yaml:"max-ttl" default:"24h"` // 覆盖最大 TTL
	} `yaml:"cache"`

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
