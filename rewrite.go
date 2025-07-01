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
		switch qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: s.Options.Cache.MinTTL},
				A:   net.ParseIP(rule.Value).To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: s.Options.Cache.MinTTL},
				AAAA: net.ParseIP(rule.Value).To16(),
			})
		case dns.TypeTXT:
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: qtype, Class: dns.ClassINET, Ttl: s.Options.Cache.MinTTL},
				Txt: []string{rule.Value},
			})
		case dns.TypeCNAME:
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: s.Options.Cache.MinTTL},
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
