package godns

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/taodev/godns/pkg/bootstrap"
	"github.com/taodev/pkg/geodb"
)

type DnsServer struct {
	Options *Options
	logger  *slog.Logger

	udpServer *dns.Server
	dohServer *http.Server

	upstream *UpstreamManager

	router *Router

	cache *Cache

	closeCh   chan struct{}
	closeOnce sync.Once
}

func (s *DnsServer) init() (err error) {
	opts := s.Options

	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: opts.LoggerLevel(),
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					// 自定义时间格式：2006-01-02 15:04:05
					t := a.Value.Time()
					a.Value = slog.StringValue(t.Format("2006-01-02 15:04:05"))
				}
				return a
			},
		}))
		slog.SetDefault(s.logger)
	}

	geodb.GeoSitePath = opts.GeoSite

	// 初始化 bootstrap dns
	if err := bootstrap.SetDNS(opts.BootstrapDNS); err != nil {
		return err
	}
	slog.Info("bootstrap dns", "dns", opts.BootstrapDNS)

	// 初始化缓存
	s.cache, err = NewCache(opts.Cache.MaxCounters, opts.Cache.MaxCost, opts.Cache.BufferItems, opts.Cache.TTL)
	if err != nil {
		return err
	}

	s.upstream = NewUpstreamManager(opts.Upstream)
	s.router, err = NewRouter(opts.Route, opts.DefaultUpstream)
	if err != nil {
		return err
	}
	err = s.router.Check(s.upstream)
	if err != nil {
		return err
	}

	s.closeCh = make(chan struct{})

	if len(opts.UDP) > 0 {
		// 初始化 udp server
		if err := s.setupUdpServer(); err != nil {
			return err
		}
	}

	if len(opts.DoH) > 0 {
		// 初始化 doh server
		if err := s.setupDohServer(); err != nil {
			return err
		}
	}

	return nil
}

func (s *DnsServer) Serve() error {
	if err := s.init(); err != nil {
		return err
	}

	<-s.closeCh

	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}

	if s.dohServer != nil {
		if err := s.dohServer.Shutdown(context.Background()); err != nil {
			slog.Error("doh server shutdown error", slog.Any("err", err))
		}
	}

	s.cache.Close()

	return nil
}

func (s *DnsServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	return nil
}

func NewDnsServer(opts *Options, logger *slog.Logger) *DnsServer {
	return &DnsServer{
		Options: opts,
		logger:  logger,
	}
}
