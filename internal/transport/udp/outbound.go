package udp

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
)

type Outbound struct {
	tag  string
	typ  string
	addr string
}

func NewOutbound(tag, typ, addr string) adapter.Outbound {
	return &Outbound{
		tag:  tag,
		typ:  typ,
		addr: addr,
	}
}

func (o *Outbound) Tag() string {
	return o.tag
}

func (o *Outbound) Type() string {
	return o.typ
}

func (o *Outbound) Exchange(req *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error) {
	now := time.Now()
	conn, err := net.Dial("udp", o.addr)
	if err != nil {
		return nil, time.Since(now), err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf, err := req.Pack()
	if err != nil {
		return nil, time.Since(now), err
	}
	_, err = conn.Write(buf)
	if err != nil {
		return nil, time.Since(now), err
	}
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, time.Since(now), err
	}
	resp = new(dns.Msg)
	err = resp.Unpack(respBuf[:n])
	if err != nil {
		return nil, time.Since(now), err
	}
	resp.Id = req.Id
	return resp, time.Since(now), nil
}

func (o *Outbound) Close() {
}
