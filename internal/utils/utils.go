package utils

import (
	"github.com/miekg/dns"
)

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
