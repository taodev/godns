package godns

import (
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func (s *DnsServer) rewrite(domain string, qtype uint16) (*dns.Msg, bool) {
	// q := r.Question[0]
	// qtype := q.Qtype
	query := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range s.Options.Rewrite {
		if !strings.EqualFold(query, rule.Domain) {
			continue
		}
		targetType, ok := dns.StringToType[rule.Type]
		if !ok || qtype != targetType {
			continue
		}
		// 构建重写响应
		resp := new(dns.Msg)
		// resp.SetReply(r)
		// resp.RecursionAvailable = true

		// 处理 NXDOMAIN 响应
		if rule.ResponseType == "nxdomain" || rule.Type == "NX" {
			resp.Rcode = dns.RcodeNameError
			return resp, false
		}

		// 处理正常记录响应（A/AAAA/TXT 等）
		switch qtype {
		case dns.TypeA:
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(s.cache.ttl.Seconds()), // 使用缓存 TTL
				},
				A: net.ParseIP(rule.Value).To4(),
			}
			resp.Answer = append(resp.Answer, a)
		case dns.TypeAAAA:
			aaaa := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(s.cache.ttl.Seconds()),
				},
				AAAA: net.ParseIP(rule.Value).To16(),
			}
			resp.Answer = append(resp.Answer, aaaa)
		case dns.TypeTXT:
			txt := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    uint32(s.cache.ttl.Seconds()),
				},
				Txt: []string{rule.Value},
			}
			resp.Answer = append(resp.Answer, txt)
		default:
			slog.Warn("unsupported rewrite type", "type", rule.Type)
			return nil, false
		}
		slog.Info("domain rewritten", "domain", domain, "type", rule.Type, "target", rule.Value)
		return resp, true
	}
	return nil, false
}
