package godns

import (
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *DnsServer) exchange(ri *RequestInfo, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	now := time.Now()

	// 移除末尾的.
	q := r.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 检查是否需要重写
	if rewrite, ok := s.rewrite(domain, r); ok {
		updateMsgTTL(rewrite, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
		rtt := time.Since(now)
		slog.Info("request", "upstream", "rewrite", "domain", domain, "qtype", dns.TypeToString[q.Qtype], "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)
		return rewrite, rtt, nil
	}

	// 查询缓存
	if resp, ok := s.cache.Get(domain, q.Qtype); ok {
		cacheResp := resp.M.Copy()
		cacheResp.Id = r.Id
		if resp.IsExpired() {
			// 异步刷新缓存
			go func(domain string, qtype uint16, question dns.Question) {
				name := s.router.Route(domain)
				msg := new(dns.Msg)
				msg.SetQuestion(question.Name, question.Qtype)

				refreshResp, rtt, refreshErr := s.upstream.Exchange(name, msg)
				if refreshErr != nil {
					slog.Warn("dns async refresh error", "error", refreshErr, "upstream", name, "domain", question.Name, "qtype", dns.TypeToString[qtype])
					return
				}
				if refreshResp.Rcode != dns.RcodeSuccess {
					slog.Warn("dns async refresh failed", "rcode", refreshResp.Rcode, "upstream", name, "domain", question.Name, "qtype", dns.TypeToString[qtype])
					return
				}
				updateMsgTTL(refreshResp, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
				s.cache.Set(domain, qtype, refreshResp.Copy())
				slog.Info("dns async refresh", "rcode", refreshResp.Rcode, "rtt", rtt, "upstream", name, "question", question.Name)
			}(domain, q.Qtype, q)
		}
		rtt := time.Since(now)
		slog.Info("request", "upstream", "cache", "domain", domain, "qtype", dns.TypeToString[q.Qtype], "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)
		return cacheResp, rtt, nil
	}

	name := s.router.Route(domain)
	resp, rtt, err := s.upstream.Exchange(name, r)
	if err != nil {
		slog.Warn("dns upstream exchange error", "error", err, "upstream", name, "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return nil, time.Since(now), err
	}
	if resp.Rcode != dns.RcodeSuccess {
		slog.Warn("dns upstream exchange failed", "rcode", resp.Rcode, "upstream", name, "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return resp, time.Since(now), nil
	}

	updateMsgTTL(resp, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
	s.cache.Set(domain, q.Qtype, resp.Copy())
	slog.Info("request", "upstream", name, "domain", domain, "qtype", dns.TypeToString[q.Qtype], "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)

	return resp, time.Since(now), nil
}
