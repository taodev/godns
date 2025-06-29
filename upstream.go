package godns

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/pkg/bootstrap"
)

type Upstream interface {
	Name() string
	Exchange(in *dns.Msg) (*dns.Msg, time.Duration, error)
}

type UdpClient struct {
	name string
	Addr string
	Host string
	Port string
}

func (c UdpClient) Name() string {
	return c.name
}

func (c *UdpClient) Exchange(in *dns.Msg) (*dns.Msg, time.Duration, error) {
	client := new(dns.Client)
	client.Net = "udp"
	return client.Exchange(in, c.Addr)
}

type DoHClient struct {
	name string
	Addr string
	Host string
	Port string
}

func (c DoHClient) Name() string {
	return c.name
}

func (c *DoHClient) Exchange(in *dns.Msg) (*dns.Msg, time.Duration, error) {
	now := time.Now()
	packed, err := in.Pack()
	if err != nil {
		slog.Warn("dns msg pack failed", "error", err)
		return nil, time.Since(now), err
	}

	req, err := http.NewRequest(http.MethodPost, c.Addr, bytes.NewReader(packed))
	if err != nil {
		slog.Warn("dns doh new request failed", "url", c.Addr, "error", err)
		return nil, time.Since(now), err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: c.Host,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("dns doh do request failed", "url", c.Addr, "error", err)
		return nil, time.Since(now), err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("dns doh read body failed", "error", err)
		return nil, time.Since(now), err
	}

	var reply dns.Msg
	if err := reply.Unpack(respBody); err != nil {
		slog.Warn("dns msg unpack failed", "error", err)
		return nil, time.Since(now), err
	}
	// 修复响应 ID
	reply.Id = in.Id
	return &reply, time.Since(now), nil
}

type UpstreamManager struct {
	upstreams map[string]Upstream
	locker    sync.RWMutex

	defaultUpstream Upstream
}

// 添加 Upstream
func (m *UpstreamManager) Add(name string, addr string) {
	m.locker.Lock()
	defer m.locker.Unlock()

	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		slog.Error("invalid upstream", "addr", addr, "error", err)
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
	case "udp":
		if port == "" {
			port = "53"
		}
		m.upstreams[name] = &UdpClient{
			name: name,
			Addr: net.JoinHostPort(ip, port),
			Host: host,
			Port: port,
		}
	case "https":
		if port == "" {
			port = "443"
		}
		u.Host = net.JoinHostPort(ip, port)
		m.upstreams[name] = &DoHClient{
			name: name,
			Addr: u.String(),
			Host: host,
			Port: port,
		}
	default:
		// 暂时不支持的协议
		slog.Error("unsupported upstream protocol", "protocol", u.Scheme, "addr", addr)
	}
	slog.Info("add upstream", "name", name, "addr", addr)
}

// 获取 Upstream
func (m *UpstreamManager) Get(name string) (Upstream, bool) {
	m.locker.RLock()
	defer m.locker.RUnlock()
	upstream, ok := m.upstreams[name]
	return upstream, ok
}

// 移除 Upstream
func (m *UpstreamManager) Remove(name string) {
	m.locker.Lock()
	defer m.locker.Unlock()
	delete(m.upstreams, name)
}

func (m *UpstreamManager) SetDefault(name string) {
	m.locker.Lock()
	defer m.locker.Unlock()
	m.defaultUpstream = m.upstreams[name]
}

// 请求
func (m *UpstreamManager) Exchange(name string, in *dns.Msg) (*dns.Msg, time.Duration, error) {
	if len(name) <= 0 {
		return m.defaultUpstream.Exchange(in)
	}

	upstream, ok := m.Get(name)
	if !ok {
		return nil, 0, fmt.Errorf("upstream:%s not found", name)
	}
	return upstream.Exchange(in)
}

func NewUpstreamManager(opts map[string]string) *UpstreamManager {
	m := &UpstreamManager{
		upstreams: make(map[string]Upstream),
	}

	for name, addr := range opts {
		m.Add(name, addr)
		if m.defaultUpstream == nil {
			m.defaultUpstream = m.upstreams[name]
		}
	}

	return m
}
