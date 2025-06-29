package godns

import (
	"log/slog"
	"strings"
	"time"

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
				upstream, ok := s.router.Route(domain)
				var rtt time.Duration
				var refreshResp *dns.Msg
				var refreshErr error
				msg := new(dns.Msg)
				msg.SetQuestion(question.Name, question.Qtype)
				if ok {
					refreshResp, rtt, refreshErr = s.upstream.Exchange(upstream, msg)
				} else {
					upstream = s.upstream.defaultUpstream.Name()
					refreshResp, rtt, refreshErr = s.upstream.defaultUpstream.Exchange(msg)
				}
				if refreshErr == nil && refreshResp != nil && refreshResp.Rcode == dns.RcodeSuccess {
					s.cache.Set(domain, qtype, refreshResp.Copy())
					slog.Info("dns async refresh", "rcode", refreshResp.Rcode, "rtt", rtt, "upstream", upstream, "question", question.Name)
				}
			}(domain, q.Qtype, q)
		}

		return cacheResp, nil
	}

	upstream, ok := s.router.Route(domain)
	var rtt time.Duration
	if ok {
		resp, rtt, err = s.upstream.Exchange(upstream, r)
	} else {
		upstream = s.upstream.defaultUpstream.Name()
		resp, rtt, err = s.upstream.defaultUpstream.Exchange(r)
	}

	if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
		s.cache.Set(domain, q.Qtype, resp.Copy())
		slog.Info("dns", "rcode", resp.Rcode, "rtt", rtt, "upstream", upstream, "question", q.Name)
	}

	return
}
