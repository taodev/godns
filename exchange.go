package godns

import (
	"log/slog"
	"strings"

	"github.com/miekg/dns"
)

func (s *DnsServer) exchange(r *dns.Msg) (resp *dns.Msg, err error) {
	// 移除末尾的.
	q := r.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 检查是否需要重写
	if rewrite, ok := s.rewrite(domain, r); ok {
		return rewrite, nil
	}

	// 查询缓存
	if resp, ok := s.cache.Get(domain, q.Qtype); ok {
		cacheResp := resp.M.Copy()
		cacheResp.Id = r.Id
		slog.Debug("dns hit cache", "domain", q.Name)

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

		return cacheResp, nil
	}

	name := s.router.Route(domain)
	resp, rtt, err := s.upstream.Exchange(name, r)
	if err != nil {
		slog.Warn("dns upstream exchange error", "error", err, "upstream", name, "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		slog.Warn("dns upstream exchange failed", "rcode", resp.Rcode, "upstream", name, "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return resp, nil
	}

	updateMsgTTL(resp, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
	s.cache.Set(domain, q.Qtype, resp.Copy())
	slog.Info("dns", "rcode", resp.Rcode, "rtt", rtt, "upstream", name, "question", q.Name)

	return resp, nil
}
