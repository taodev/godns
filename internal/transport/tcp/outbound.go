package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/godns/pkg/bootstrap"
	"github.com/taodev/stcp"
	"github.com/taodev/stcp/key"
)

type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type asyncResp struct {
	resp *dns.Msg
	rtt  time.Duration
	err  error
}

type asyncRequest struct {
	req *dns.Msg
	ch  chan *asyncResp
}

type Outbound struct {
	tag      string
	typ      string
	addr     string
	hostname string
	dialer   dialer

	keepAlive bool
	requestCh chan *asyncRequest
	closeCh   chan struct{}
	connected atomic.Bool
	conn      net.Conn
	once      sync.Once
	wait      sync.WaitGroup
}

func NewOutbound(tag, typ, addr string, hostname string, privateKey, serverPub string) adapter.Outbound {
	out := &Outbound{
		tag:      tag,
		typ:      typ,
		addr:     addr,
		hostname: hostname,
	}
	switch typ {
	case "tcp":
		out.dialer = &net.Dialer{}
	case "tls":
		out.dialer = &tls.Dialer{
			Config: &tls.Config{
				ServerName: hostname,
			},
		}
	}
	return out
}

func NewOutboundSTCP(tag, addr string, defaultKey string) (outbound adapter.Outbound, err error) {
	u, err := url.Parse(addr)
	if err != nil {
		slog.Error("invalid outbound", "addr", addr, "error", err)
		return nil, err
	}
	if u.Scheme != "stcp" {
		return nil, fmt.Errorf("invalid outbound, scheme must be stcp")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "553"
	}
	ip := host
	if net.ParseIP(host) == nil {
		// 处理域名
		ip, err = bootstrap.Cache(host)
		if err != nil {
			slog.Error("dns bootstrap failed", "error", err)
			return nil, err
		}
	}
	k := u.User.Username()
	if k == "" {
		k = defaultKey
	}
	config, err := stcp.NewClientConfig()
	if err != nil {
		return nil, err
	}
	config.PrivateKey, err = key.Base64(k)
	if err != nil {
		return nil, err
	}
	pub := u.Query().Get("serverPub")
	if pub == "" {
		return nil, fmt.Errorf("serverPub is required")
	}
	config.ServerPub, err = key.Base64(pub)
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		tag:       tag,
		typ:       utils.TypeSTCP,
		addr:      net.JoinHostPort(ip, port),
		hostname:  host,
		dialer:    &stcp.Dialer{Config: config},
		keepAlive: u.Query().Get("keepAlive") == "true",
	}

	if out.keepAlive {
		out.requestCh = make(chan *asyncRequest, 128)
		out.closeCh = make(chan struct{})
		out.wait.Add(1)
		go out.requestLoop()
	}

	return out, nil
}

func (h *Outbound) Tag() string {
	return h.tag
}

func (h *Outbound) Type() string {
	return h.typ
}

func (h *Outbound) Exchange(in *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error) {
	if !h.keepAlive {
		return h.exchange(in)
	}

	req := &asyncRequest{req: in, ch: make(chan *asyncResp)}
	h.requestCh <- req
	select {
	case <-h.closeCh:
		return nil, 0, fmt.Errorf("closed")
	case r := <-req.ch:
		return r.resp, r.rtt, r.err
	}
}

func (h *Outbound) exchange(in *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error) {
	now := time.Now()
	conn, err := h.dial(h.addr)
	if err != nil {
		return nil, time.Since(now), err
	}
	defer func() {
		if !h.keepAlive {
			conn.Close()
		}
	}()
	if err = conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return nil, time.Since(now), err
	}
	if err = write(conn, in); err != nil {
		return nil, time.Since(now), err
	}
	if resp, err = read(conn); err != nil {
		return nil, time.Since(now), err
	}
	// 修复响应 ID
	resp.Id = in.Id
	return resp, time.Since(now), nil
}

func (h *Outbound) requestLoop() {
	defer h.wait.Done()

	slog.Info("requestLoop", "tag", h.tag)
	h.dial(h.addr)

	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-h.closeCh:
			return
		case <-ticker.C:
			conn, err := h.dial(h.addr)
			if err != nil {
				slog.Error("dial failed", "error", err)
				h.dial(h.addr)
				continue
			}
			if err = h.ping(conn); err != nil {
				slog.Error("ping failed", "error", err)
				h.connected.Store(false)
				conn.Close()
				h.dial(h.addr)
				continue
			}
			slog.Debug("ping", "tag", h.tag)
		case req := <-h.requestCh:
			resp, rtt, err := h.exchange(req.req)
			req.ch <- &asyncResp{resp: resp, rtt: rtt, err: err}
		}
	}
}

func (h *Outbound) dial(addr string) (net.Conn, error) {
	if !h.keepAlive {
		return h.dialer.DialContext(context.Background(), "tcp", addr)
	}

	if h.connected.Load() {
		return h.conn, nil
	}

	conn, err := h.dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	h.conn = conn
	h.connected.Store(true)
	return conn, nil
}

func (h *Outbound) ping(conn net.Conn) (err error) {
	if !h.keepAlive {
		return nil
	}
	if err = conn.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return err
	}
	// 发送心跳包
	if _, err = conn.Write([]byte{0x00, 0x00}); err != nil {
		return err
	}
	return nil
}

func (h *Outbound) Close() {
	h.once.Do(func() {
		if h.keepAlive {
			close(h.closeCh)
			h.connected.Store(false)
			h.wait.Wait()
			h.conn.Close()
		}
	})
}
