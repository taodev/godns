package http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/route"
	"github.com/taodev/godns/internal/utils"
)

const (
	defaultTimeout = 10 * time.Second
)

type Options struct {
	Type   string `yaml:"type"`
	Domain string `yaml:"domain"`
	Addr   string `yaml:"addr"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

type Inbound struct {
	options    *Options
	listener   net.Listener
	httpServer *http.Server
	router     *route.Router
	wait       sync.WaitGroup
	running    atomic.Bool
}

func NewInbound(ctx context.Context, router *route.Router, options *Options) *Inbound {
	return &Inbound{
		router:  router,
		options: options,
	}
}

func (h *Inbound) Start() (err error) {
	h.listener, err = net.Listen("tcp", h.options.Addr)
	if err != nil {
		return err
	}
	// 路由设置
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", h.handleDNSQuery)

	h.httpServer = &http.Server{
		Addr:              h.options.Addr,
		Handler:           mux,
		ReadHeaderTimeout: defaultTimeout,
		WriteTimeout:      defaultTimeout,
	}

	if h.options.Type == utils.TypeHTTPS {
		var cert tls.Certificate
		if cert, err = tls.LoadX509KeyPair(h.options.Cert, h.options.Key); err != nil {
			return err
		}
		h.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"}, // 非常关键！
		}
	}

	// 启动 HTTP 服务器
	h.wait.Add(1)
	go func() {
		defer h.wait.Done()
		if h.options.Type == utils.TypeHTTPS {
			if err := h.httpServer.ServeTLS(h.listener, "", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("http server serve failed", "err", err)
			}
		} else {
			if err := h.httpServer.Serve(h.listener); err != nil && err != http.ErrServerClosed {
				slog.Error("http server serve failed", "err", err)
			}
		}
	}()

	h.running.Store(true)
	slog.Info(fmt.Sprintf("[inbound] %s: %s started", h.options.Type, h.options.Addr))
	return nil
}

func (h *Inbound) Close() (err error) {
	h.running.Store(false)
	if err = h.httpServer.Shutdown(context.Background()); err != nil {
		slog.Error("http server shutdown failed", "err", err)
	}
	h.wait.Wait()
	return err
}

func (h *Inbound) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	var (
		err  error
		req  *dns.Msg
		resp *dns.Msg
	)
	paddr, _, err := remoteAddr(r)
	if err != nil {
		slog.Error("get remote addr failed", "err", err)
		return
	}
	req, statusCode := readMsg(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}
	if resp, err = h.router.Exchange(req, h.options.Type, paddr.Addr().String()); err != nil {
		resp = utils.NewMsgSERVFAIL(req)
	}
	if h.options.Domain != "" {
		w.Header().Set("Server", h.options.Domain)
	}
	if err = writeMsg(w, resp); err != nil {
		return
	}
}

func readMsg(r *http.Request) (req *dns.Msg, statusCode int) {
	var buf []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if len(buf) == 0 || err != nil {
			return nil, http.StatusBadRequest
		}
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType
		}
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		r.Body.Close()
	default:
		return nil, http.StatusMethodNotAllowed
	}
	req = &dns.Msg{}
	if err = req.Unpack(buf); err != nil {
		return nil, http.StatusBadRequest
	}
	return req, http.StatusOK
}

func writeMsg(w http.ResponseWriter, resp *dns.Msg) (err error) {
	if resp == nil {
		// Indicate the response's absence via a http.StatusInternalServerError.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	bytes, err := resp.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("packing message: %w", err)
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(bytes)
	return err
}

// realIPFromHdrs extracts the actual client's IP address from the first
// suitable r's header.  It returns an error if r doesn't contain any
// information about real client's IP address.  Current headers priority is:
//
//  1. [httphdr.CFConnectingIP]
//  2. [httphdr.TrueClientIP]
//  3. [httphdr.XRealIP]
//  4. [httphdr.XForwardedFor]
func realIPFromHdrs(r *http.Request) (realIP netip.Addr, err error) {
	for _, h := range []string{
		"Cf-Connecting-Ip",
		"True-Client-Ip",
		"X-Real-Ip",
	} {
		realIP, err = netip.ParseAddr(strings.TrimSpace(r.Header.Get(h)))
		if err == nil {
			return realIP, nil
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	firstComma := strings.IndexByte(xff, ',')
	if firstComma > 0 {
		xff = xff[:firstComma]
	}

	return netip.ParseAddr(strings.TrimSpace(xff))
}

// remoteAddr returns the real client's address and the IP address of the latest
// proxy server if any.
func remoteAddr(r *http.Request) (addr, prx netip.AddrPort, err error) {
	host, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}

	realIP, err := realIPFromHdrs(r)
	if err != nil {
		return host, netip.AddrPort{}, nil
	}

	// TODO(a.garipov): Add port if we can get it from headers like X-Real-Port,
	// X-Forwarded-Port, etc.
	addr = netip.AddrPortFrom(realIP, 0)

	return addr, host, nil
}
