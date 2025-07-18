package transport

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/transport/http"
	"github.com/taodev/godns/internal/transport/tcp"
	"github.com/taodev/godns/internal/transport/udp"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/godns/pkg/bootstrap"
)

type Manager struct {
	access  sync.RWMutex
	started atomic.Bool

	outbounds map[string]adapter.Outbound
	stcpKey   string
}

func NewManager(opts map[string]string, stcpKey string) *Manager {
	m := &Manager{
		outbounds: make(map[string]adapter.Outbound),
		stcpKey:   stcpKey,
	}
	for name, addr := range opts {
		m.Add(name, addr)
	}
	return m
}

func (m *Manager) Add(tag string, addr string) {
	m.access.Lock()
	defer m.access.Unlock()

	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		slog.Error("invalid outbound", "addr", addr, "error", err)
		return
	}
	scheme := u.Scheme
	if len(scheme) == 0 {
		scheme = utils.TypeUDP
	}
	host := u.Hostname()
	port := u.Port()
	ip := host
	if net.ParseIP(host) == nil {
		// 处理域名
		ip, err = bootstrap.Cache(host)
		if err != nil {
			slog.Error("dns bootstrap failed", "error", err)
			return
		}
	}

	switch u.Scheme {
	case utils.TypeTCP:
		if len(port) == 0 {
			port = "53"
		}
		m.outbounds[tag] = tcp.NewOutbound(tag, u.Scheme, net.JoinHostPort(ip, port), host, "", "")
	case utils.TypeTLS:
		if len(port) == 0 {
			port = "853"
		}
		m.outbounds[tag] = tcp.NewOutbound(tag, u.Scheme, net.JoinHostPort(ip, port), host, "", "")
	case utils.TypeSTCP:
		m.outbounds[tag], err = tcp.NewOutboundSTCP(tag, addr, m.stcpKey)
		if err != nil {
			slog.Error("invalid outbound", "tag", tag, "error", err)
			return
		}
	case utils.TypeHTTP, utils.TypeHTTPS:
		m.outbounds[tag] = http.NewOutbound(tag, u.Scheme, addr, ip)
	case utils.TypeUDP:
		if len(port) == 0 {
			port = "53"
		}
		m.outbounds[tag] = udp.NewOutbound(tag, u.Scheme, net.JoinHostPort(ip, port))
	default:
		// 暂时不支持的协议
		slog.Error("unsupported upstream protocol", "protocol", u.Scheme, "addr", addr)
	}
}

// 获取 Outbound
func (m *Manager) Get(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	defer m.access.RUnlock()
	outbound, ok := m.outbounds[tag]
	return outbound, ok
}

// 移除 Outbound
func (m *Manager) Remove(tag string) {
	m.access.Lock()
	defer m.access.Unlock()
	delete(m.outbounds, tag)
}

// 请求
func (m *Manager) Exchange(tag string, in *dns.Msg) (*dns.Msg, time.Duration, error) {
	qname := in.Question[0].Name
	qname, err := idna.ToASCII(qname)
	if err != nil {
		return nil, 0, err
	}
	in.Question[0].Name = qname

	outbound, ok := m.Get(tag)
	if !ok {
		return nil, 0, fmt.Errorf("outbound:%s not found", tag)
	}
	return outbound.Exchange(in)
}

func (m *Manager) Close() {
	for _, outbound := range m.outbounds {
		outbound.Close()
	}
}

// func (m *Manager) Start(opts map[string]string) (err error) {
// 	if m.started.Load() {
// 		panic("already started")
// 	}
// 	m.started.Store(true)
// 	for name, addr := range opts {
// 		m.Add(name, addr)
// 	}
// 	return nil
// }
