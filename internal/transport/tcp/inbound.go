package tcp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/stcp"
)

const (
	defaultTimeout = 120 * time.Second
)

type Options struct {
	Type string `yaml:"-"`
	Addr string `yaml:"addr"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Inbound struct {
	options  *Options
	listener net.Listener
	router   *route.Router
	wait     sync.WaitGroup
	running  atomic.Bool
}

func NewInbound(ctx context.Context, router *route.Router, options *Options) *Inbound {
	return &Inbound{
		router:  router,
		options: options,
	}
}

func (h *Inbound) Start() (err error) {
	switch h.options.Type {
	case utils.TypeTCP:
		h.listener, err = net.Listen("tcp", h.options.Addr)
	case utils.TypeTLS:
		var cert tls.Certificate
		if cert, err = tls.LoadX509KeyPair(h.options.Cert, h.options.Key); err != nil {
			return err
		}
		h.listener, err = tls.Listen("tcp", h.options.Addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	case utils.TypeSTCP:
		serverCtx, errCtx := stcp.NewServerContext()
		if errCtx != nil {
			return errCtx
		}
		serverCtx.PrivateKey, errCtx = base64.RawURLEncoding.DecodeString(h.options.Key)
		if errCtx != nil {
			return errCtx
		}
		h.listener, err = stcp.Listen("tcp", h.options.Addr, serverCtx)
	default:
		return fmt.Errorf("unknown inbound type: %s", h.options.Type)
	}
	if err != nil {
		return err
	}
	h.running.Store(true)
	h.wait.Add(1)
	go h.handleAccept()
	slog.Info(fmt.Sprintf("[inbound] %s: %s started", h.options.Type, h.options.Addr))
	return nil
}

func (h *Inbound) Close() error {
	h.running.Store(false)
	err := h.listener.Close()
	h.wait.Wait()
	return err
}

func (h *Inbound) handleAccept() {
	defer h.wait.Done()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			// 判断是否是 Listener 主动关闭导致的错误
			if errors.Is(err, net.ErrClosed) {
				log.Println("listener closed, exiting accept loop")
				return
			}

			// 判断是否是超时错误（一般设置了 deadline 时才会有）
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Println("accept timeout, continue...")
				continue
			}

			// 其他错误，视为不可恢复
			slog.Error("accept error", "err", err)
			return
		}
		go h.handleConn(conn)
	}
}

func (h *Inbound) handleConn(conn net.Conn) {
	defer conn.Close()
	var (
		err  error
		req  *dns.Msg
		resp *dns.Msg
	)
	for h.running.Load() {
		if err = conn.SetDeadline(time.Now().Add(3 * time.Minute)); err != nil {
			return
		}
		if req, err = read(conn); err != nil {
			return
		}
		if req == nil {
			slog.Info("recv ping", "addr", conn.RemoteAddr())
			continue
		}
		raddr, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
		if resp, err = h.router.Exchange(req, h.options.Type, raddr.Addr().String()); err != nil {
			resp = utils.NewMsgSERVFAIL(req)
		}
		if err = write(conn, resp); err != nil {
			return
		}
	}
}
