package godns

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/taodev/godns/internal/cache"
	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/transport"
	"github.com/taodev/godns/internal/transport/http"
	"github.com/taodev/godns/internal/transport/tcp"
	"github.com/taodev/godns/internal/transport/udp"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/godns/pkg/bootstrap"
	"github.com/taodev/pkg/geodb"
)

type DnsServer struct {
	Options *Options
	logger  *slog.Logger

	inboundUDP   *udp.Inbound
	inboundTCP   *tcp.Inbound
	inboundTLS   *tcp.Inbound
	inboundSTCP  *tcp.Inbound
	inboundHTTP  *http.Inbound
	inboundHTTPS *http.Inbound

	outbound *transport.Manager
	router   *route.Router
	rewriter *rewrite.Rewriter
	cache    *cache.Cache

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
	slog.Info("bootstrap dns: " + strings.Join(opts.BootstrapDNS, ", "))

	// 初始化缓存
	if s.cache, err = cache.New(&opts.Cache); err != nil {
		return err
	}
	s.outbound = transport.NewManager(opts.Outbounds, opts.StcpKey)
	s.rewriter = rewrite.NewRewriter(opts.Rewrite)
	if s.router, err = route.New(&opts.Route, s.outbound, s.rewriter, s.cache); err != nil {
		return err
	}

	s.closeCh = make(chan struct{})
	s.errorCh = make(chan error)

	if err = s.cache.Start(); err != nil {
		return err
	}

	// new version
	if opts.Inbounds.UDP != nil {
		opts.Inbounds.UDP.Type = utils.TypeUDP
		s.inboundUDP = udp.NewInbound(context.Background(), s.router, opts.Inbounds.UDP)
		if err = s.inboundUDP.Start(); err != nil {
			return err
		}
	}
	if opts.Inbounds.TCP != nil {
		opts.Inbounds.TCP.Type = utils.TypeTCP
		s.inboundTCP = tcp.NewInbound(context.Background(), s.router, opts.Inbounds.TCP)
		if err = s.inboundTCP.Start(); err != nil {
			return err
		}
	}
	if opts.Inbounds.TLS != nil {
		opts.Inbounds.TLS.Type = utils.TypeTLS
		s.inboundTLS = tcp.NewInbound(context.Background(), s.router, opts.Inbounds.TLS)
		if err = s.inboundTLS.Start(); err != nil {
			return err
		}
	}
	if opts.Inbounds.STCP != nil {
		opts.Inbounds.STCP.Type = utils.TypeSTCP
		if len(opts.Inbounds.STCP.Key) == 0 {
			opts.Inbounds.STCP.Key = opts.StcpKey
		}
		s.inboundSTCP = tcp.NewInbound(context.Background(), s.router, opts.Inbounds.STCP)
		if err = s.inboundSTCP.Start(); err != nil {
			return err
		}
	}
	if opts.Inbounds.HTTP != nil {
		opts.Inbounds.HTTP.Type = utils.TypeHTTP
		s.inboundHTTP = http.NewInbound(context.Background(), s.router, opts.Inbounds.HTTP)
		if err = s.inboundHTTP.Start(); err != nil {
			return err
		}
	}
	if opts.Inbounds.HTTPS != nil {
		opts.Inbounds.HTTPS.Type = utils.TypeHTTPS
		s.inboundHTTPS = http.NewInbound(context.Background(), s.router, opts.Inbounds.HTTPS)
		if err = s.inboundHTTPS.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (s *DnsServer) Serve() (err error) {
	s.wg.Add(1)
	defer s.wg.Done()
	s.running = true
	if err := s.init(); err != nil {
		return err
	}

	select {
	case err = <-s.errorCh:
		s.close()
	case <-s.closeCh:
	}

	// new version
	if s.inboundUDP != nil {
		s.inboundUDP.Close()
	}
	if s.inboundTCP != nil {
		s.inboundTCP.Close()
	}
	if s.inboundTLS != nil {
		s.inboundTLS.Close()
	}
	if s.inboundSTCP != nil {
		s.inboundSTCP.Close()
	}
	if s.inboundHTTP != nil {
		s.inboundHTTP.Close()
	}
	if s.inboundHTTPS != nil {
		s.inboundHTTPS.Close()
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
