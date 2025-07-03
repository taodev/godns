package udp

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
)

type Options struct {
	Type string
	Addr string
}

type Inbound struct {
	options *Options
	router  adapter.Router
	conn    net.PacketConn
	closeCh chan struct{}
}

func NewInbound(ctx context.Context, router adapter.Router, options *Options) *Inbound {
	return &Inbound{
		options: options,
		router:  router,
		closeCh: make(chan struct{}),
	}
}

func (i *Inbound) Start() error {
	addr := ":53"
	if i.options != nil && i.options.Addr != "" {
		addr = i.options.Addr
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	i.conn = conn
	go i.serve()
	slog.Info("UDP inbound started", "addr", addr)
	return nil
}

func (i *Inbound) serve() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-i.closeCh:
			return
		default:
		}
		n, addr, err := i.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				slog.Warn("UDP read error", "error", err)
				continue
			}
			return
		}
		go i.handlePacket(buf[:n], addr)
	}
}

func (i *Inbound) handlePacket(data []byte, addr net.Addr) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		slog.Warn("Failed to unpack DNS message", "error", err)
		return
	}
	raddr, _ := netip.ParseAddrPort(addr.String())
	resp, err := i.router.Exchange(msg, i.options.Type, raddr.Addr().String())
	if err != nil {
		slog.Warn("DNS exchange error", "error", err)
		return
	}
	if resp == nil {
		return
	}
	out, err := resp.Pack()
	if err != nil {
		slog.Warn("Failed to pack DNS response", "error", err)
		return
	}
	_, err = i.conn.WriteTo(out, addr)
	if err != nil {
		slog.Warn("Failed to write DNS response", "error", err)
	}
}

func (i *Inbound) Close() error {
	close(i.closeCh)
	if i.conn != nil {
		return i.conn.Close()
	}
	return nil
}
