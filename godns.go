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

	udpServer  *dns.Server
	tcpServer  *dns.Server
	stcpServer *StcpServer
	dohServer  *http.Server

	upstream *UpstreamManager

	router *Router

	cache *Cache

	closeCh   chan struct{}
	closeOnce sync.Once
	errorCh   chan error
	wg        sync.WaitGroup
	// 运行状态
	running bool
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

	s.upstream = NewUpstreamManager(opts)
	s.router, err = NewRouter(opts.Route, opts.DefaultUpstream)
	if err != nil {
		return err
	}
	err = s.router.Check(s.upstream)
	if err != nil {
		return err
	}

	s.closeCh = make(chan struct{})
	s.errorCh = make(chan error)

	if len(opts.UDP) > 0 {
		// 初始化 udp server
		if err := s.setupUdpServer(); err != nil {
			return err
		}
	}

	if len(opts.TCP) > 0 {
		// 初始化 tcp server
		if err := s.setupTcpServer(); err != nil {
			return err
		}
	}

	if len(opts.STCP.Addr) > 0 {
		// 初始化 stcp server
		if err := s.setupStcpServer(); err != nil {
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

func (s *DnsServer) Serve() (err error) {
	s.running = true
	if err := s.init(); err != nil {
		return err
	}

	select {
	case err = <-s.errorCh:
		s.close()
	case <-s.closeCh:
	}

	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}

	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}

	if s.stcpServer != nil {
		s.stcpServer.Shutdown()
	}

	if s.dohServer != nil {
		if err := s.dohServer.Shutdown(context.Background()); err != nil {
			slog.Error("doh server shutdown error", slog.Any("err", err))
		}
	}

	s.cache.Close()

	slog.Debug("dns server close")
	return err
}

func (s *DnsServer) close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	return nil
}

func (s *DnsServer) Shutdown() (err error) {
	err = s.close()
	if err != nil {
		return err
	}

	if s.running {
		s.wg.Wait()
		s.running = false
	}
	return
}

func NewDnsServer(opts *Options, logger *slog.Logger) *DnsServer {
	return &DnsServer{
		Options: opts,
		logger:  logger,
	}
}
