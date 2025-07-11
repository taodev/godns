package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/utils"
)

type Outbound struct {
	tag    string
	typ    string
	url    string
	host   string
	ipAddr string
}

func NewOutbound(tag, typ, addr string, ip string) adapter.Outbound {
	u, err := url.Parse(addr)
	if err != nil {
		slog.Error("parse http outbound url failed", "addr", addr, "error", err)
		return nil
	}
	port := u.Port()
	if len(port) == 0 {
		if typ == utils.TypeHTTPS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return &Outbound{
		tag:    tag,
		typ:    typ,
		url:    addr,
		host:   u.Hostname(),
		ipAddr: net.JoinHostPort(ip, port),
	}
}

func (h *Outbound) Tag() string {
	return h.tag
}

func (h *Outbound) Type() string {
	return h.typ
}

func (h *Outbound) Exchange(req *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error) {
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such as
	// "application/dns-message", SHOULD use a DNS ID of 0 in every DNS request.
	//
	// See https://www.rfc-editor.org/rfc/rfc8484.html.
	id := req.Id
	req.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies.
		req.Id = id
		if resp != nil {
			resp.Id = id
		}
	}()

	buf, err := req.Pack()
	if err != nil {
		return nil, 0, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("User-Agent", "")
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	client := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: h.host,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				slog.Info("DialContext", "network", network, "addr", addr, "ipAddr", h.ipAddr)
				// 固定连接 IP
				dialer := &net.Dialer{Timeout: defaultTimeout}
				return dialer.DialContext(ctx, network, h.ipAddr)
			},
		},
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, 0, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status code: %d", httpResp.StatusCode)
	}

	resp = new(dns.Msg)
	err = resp.Unpack(respBody)
	if err != nil {
		return nil, 0, err
	}
	if resp.Id != req.Id {
		return nil, 0, fmt.Errorf("unexpected id: %d", resp.Id)
	}
	return resp, 0, nil
}
