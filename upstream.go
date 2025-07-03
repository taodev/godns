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
	name   string
	Scheme string
	Addr   string
	Host   string
	Port   string
}

func (c UdpClient) Name() string {
	return c.name
}

func (c *UdpClient) Exchange(in *dns.Msg) (*dns.Msg, time.Duration, error) {
	client := new(dns.Client)
	client.Net = c.Scheme
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
		resp := new(dns.Msg)
		resp.SetReply(in)
		resp.Rcode = dns.RcodeFormatError
		slog.Warn("dns msg pack failed", "error", err)
		return resp, time.Since(now), nil
	}

	req, err := http.NewRequest(http.MethodPost, c.Addr, bytes.NewReader(packed))
	if err != nil {
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
		return nil, time.Since(now), err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Since(now), err
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(respBody); err != nil {
		reply.SetReply(in)
		reply.Rcode = dns.RcodeServerFailure
		return reply, time.Since(now), nil
	}
	// 修复响应 ID
	reply.Id = in.Id
	return reply, time.Since(now), nil
}

type UpstreamManager struct {
	upstreams map[string]Upstream
	locker    sync.RWMutex
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
			name:   name,
			Addr:   net.JoinHostPort(ip, port),
			Host:   host,
			Port:   port,
			Scheme: u.Scheme,
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
		// default:
		// 	// 暂时不支持的协议
		// 	slog.Error("unsupported upstream protocol", "protocol", u.Scheme, "addr", addr)
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

// 请求
func (m *UpstreamManager) Exchange(name string, in *dns.Msg) (*dns.Msg, time.Duration, error) {
	upstream, ok := m.Get(name)
	if !ok {
		return nil, 0, fmt.Errorf("upstream:%s not found", name)
	}
	return upstream.Exchange(in)
}

func NewUpstreamManager(opts *Options) *UpstreamManager {
	m := &UpstreamManager{
		upstreams: make(map[string]Upstream),
	}

	for name, addr := range opts.Upstream {
		m.Add(name, addr)
	}

	return m
}
