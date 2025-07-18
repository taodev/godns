package rewrite

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/pkg/defaults"
	"github.com/taodev/pkg/geodb"
)

// 重写配置
type RuleOptions struct {
	// 域名
	Domain string `yaml:"domain"`
	// GeoSite
	GeoSite string `yaml:"geosite"`
	// 类型
	Type string `yaml:"type" default:"A"`
	// 值
	Value string `yaml:"value"`
	// TTL
	TTL time.Duration `yaml:"ttl" default:"60s"`
}

type Options struct {
	MinTTL time.Duration `yaml:"min-ttl" default:"600s"`
	MaxTTL time.Duration `yaml:"max-ttl" default:"24h"`
	// 规则
	Rules []RuleOptions `yaml:"rule"`
}

type Rewriter struct {
	options Options
	matcher []geodb.Matcher
}

func NewRewriter(opts Options) (*Rewriter, error) {
	defaults.Set(&opts)
	matcher := make([]geodb.Matcher, len(opts.Rules))
	var err error
	for i, rule := range opts.Rules {
		slog.Debug("rewrite rule", "rule", rule)
		if rule.GeoSite != "" {
			matcher[i], err = geodb.Site(geodb.GeoSitePath, rule.GeoSite)
			if err != nil {
				return nil, err
			}
		} else {
			matcher[i] = &geodb.DomainMatcher{Code: rule.Domain}
		}

		if rule.Domain != "" {
			matcher[i].(*geodb.DomainMatcher).Params = []*geodb.Param{
				{Key: geodb.DomainKeyFull, Val: rule.Domain},
			}
		}
	}
	return &Rewriter{
		options: opts,
		matcher: matcher,
	}, nil
}

func (r *Rewriter) Rewrite(domain string, qtype uint16) (*dns.Msg, bool) {
	query := strings.ToLower(strings.TrimSuffix(domain, "."))
	for i, rule := range r.options.Rules {
		if !r.matcher[i].Match(query) {
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

func (r *Rewriter) UpdateTTL(msg *dns.Msg) {
	max := uint32(r.options.MaxTTL.Seconds())
	min := uint32(r.options.MinTTL.Seconds())
	for _, rr := range msg.Answer {
		if min > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
		if max > 0 && rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
	for _, rr := range msg.Ns {
		if min > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
	}
	for _, rr := range msg.Extra {
		if min > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
	}
}
