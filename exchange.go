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
