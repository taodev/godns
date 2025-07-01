package godns

import (
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func (s *DnsServer) rewrite(domain string, qtype uint16) (*dns.Msg, bool) {
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
		ttl := uint32(rule.TTL.Seconds())
		if ttl <= 0 {
			ttl = uint32(s.Options.Cache.MinTTL)
		}
		switch qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP(rule.Value),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.ParseIP(rule.Value),
			})
		case dns.TypeTXT:
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{rule.Value},
			})
		case dns.TypeCNAME:
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(rule.Value),
			})
		default:
			slog.Warn("unsupported rewrite type", "type", rule.Type)
			return nil, false
		}
		return resp, true
	}
	return nil, false
}
