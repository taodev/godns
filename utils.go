package godns

import "github.com/miekg/dns"

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
