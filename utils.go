package godns

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type RequestInfo struct {
	IP      string
	Inbound string
}

func NewRequestInfoFromAddr(remoteAddr string, inbound string) (ri *RequestInfo) {
	ri = new(RequestInfo)
	if addr, err := netip.ParseAddrPort(remoteAddr); err == nil {
		ri.IP = addr.Addr().String()
	}
	ri.Inbound = inbound
	return
}

func NewRequestInfoFromHTTP(r *http.Request) (ri *RequestInfo) {
	ri = new(RequestInfo)
	// 优先从 X-Real-IP 读取
	realIP := r.Header.Get("X-Real-IP")
	if realIP == "" {
		// 退而求其次，从 X-Forwarded-For 获取第一个 IP
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			realIP = strings.TrimSpace(parts[0])
		} else {
			// 最后使用 RemoteAddr（一般是代理 IP）
			realIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	}
	ri.IP = realIP
	ri.Inbound = "DoH"
	return
}
