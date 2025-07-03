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
}

func NewManager(opts map[string]string) *Manager {
	m := &Manager{
		outbounds: make(map[string]adapter.Outbound),
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
	case utils.TypeTCP, utils.TypeTLS, utils.TypeSTCP:
		m.outbounds[tag] = tcp.NewOutbound(tag, u.Scheme, net.JoinHostPort(ip, port), u.User.Username())
	case utils.TypeHTTP, utils.TypeHTTPS:
		m.outbounds[tag] = http.NewOutbound(tag, u.Scheme, addr)
	case utils.TypeUDP:
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
	outbound, ok := m.Get(tag)
	if !ok {
		return nil, 0, fmt.Errorf("outbound:%s not found", tag)
	}
	return outbound.Exchange(in)
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
