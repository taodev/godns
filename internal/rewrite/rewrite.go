package rewrite

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// 重写配置
type Options struct {
	// 域名
	Domain string `yaml:"domain"`
	// 类型
	Type string `yaml:"type" default:"A"`
	// 值
	Value string `yaml:"value"`
	// TTL
	TTL time.Duration `yaml:"ttl" default:"60s"`
}

type Rewriter struct {
	Rules []Options
}

func NewRewriter(opts []Options) *Rewriter {
	return &Rewriter{
		Rules: opts,
	}
}

func (r *Rewriter) Rewrite(domain string, qtype uint16) (*dns.Msg, bool) {
	query := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range r.Rules {
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
