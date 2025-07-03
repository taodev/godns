package adapter

import (
	"time"

	"github.com/miekg/dns"
)

type Inbound interface {
	Type() string
	Tag() string
	Start() error
	Close() error
}

type Outbound interface {
	Tag() string
	Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error)
}

type OutboundManager interface {
	Get(tag string) (Outbound, bool)
	// Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error)
}

type Router interface {
	Exchange(request *dns.Msg, inbound string, ip string) (response *dns.Msg, err error)
}

type DnsQuery interface {
	Resolve(in *dns.Msg) (resp *dns.Msg, outboundTag string, err error)
}
