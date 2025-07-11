package tcp

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/stcp"
	"github.com/taodev/stcp/key"
)

type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Outbound struct {
	tag      string
	typ      string
	addr     string
	hostname string
	dialer   dialer
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
	case "stcp":
		config, err := stcp.NewClientConfig()
		if err != nil {
			return nil
		}
		config.PrivateKey, err = key.Base64(privateKey)
		if err != nil {
			return nil
		}
		config.ServerPub, err = key.Base64(serverPub)
		if err != nil {
			return nil
		}
		out.dialer = &stcp.Dialer{Config: config}
	}
	return out
}

func (h *Outbound) Tag() string {
	return h.tag
}

func (h *Outbound) Type() string {
	return h.typ
}

func (h *Outbound) Exchange(in *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error) {
	now := time.Now()
	conn, err := h.dial(h.addr)
	if err != nil {
		return nil, time.Since(now), err
	}
	defer conn.Close()
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

func (h *Outbound) dial(addr string) (net.Conn, error) {
	return h.dialer.DialContext(context.Background(), "tcp", addr)
}
