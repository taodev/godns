package godns

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
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

func GetMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0
	for _, rr := range msg.Answer {
		ttl := rr.Header().Ttl
		if ttl == 0 {
			continue
		}
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL == 0 {
		// 如果没有找到有效的TTL，使用默认值
		minTTL = 60 // 默认TTL为60秒
	}
	return minTTL
}

// 覆写 dns.Msg 的 ttl
func updateMsgTTL(msg *dns.Msg, minTTL, maxTTL uint32) {
	for _, rr := range msg.Answer {
		if minTTL > 0 && rr.Header().Ttl < minTTL {
			rr.Header().Ttl = minTTL
		}
		if maxTTL > 0 && rr.Header().Ttl > maxTTL {
			rr.Header().Ttl = maxTTL
		}
	}
	for _, rr := range msg.Ns {
		if minTTL > 0 && rr.Header().Ttl < minTTL {
			rr.Header().Ttl = minTTL
		}
	}
	for _, rr := range msg.Extra {
		if minTTL > 0 && rr.Header().Ttl < minTTL {
			rr.Header().Ttl = minTTL
		}
	}
}

func shouldRecurse(msg *dns.Msg, qtype uint16) (recurse bool) {
	for _, ans := range msg.Answer {
		if ans.Header().Rrtype == qtype {
			return false // 找到目标记录，停止
		}
		if ans.Header().Rrtype == dns.TypeCNAME {
			recurse = true
		}
	}
	return recurse // 既无目标类型，也无 CNAME，可能 NXDOMAIN 或空结果
}
