package godns

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *DnsServer) Exchange(r *dns.Msg) (upstream string, resp *dns.Msg, rtt time.Duration, err error) {
	if len(r.Question) == 0 {
		return "", nil, 0, fmt.Errorf("no question")
	}
	// 移除末尾的.
	q := r.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	// 查询缓存, 单条查询时才缓存
	if len(r.Question) == 1 {
		if resp, ok := s.cache.Get(domain, q.Qtype); ok {
			cacheResp := resp.M.Copy()
			cacheResp.Id = r.Id
			return "cache", cacheResp, 0, nil
		}
	}

	upstream, ok := s.router.Route(domain)
	if ok {
		resp, rtt, err = s.upstream.Exchange(upstream, r)
		return
	} else {
		upstream = s.upstream.defaultUpstream.Name()
		resp, rtt, err = s.upstream.defaultUpstream.Exchange(r)
	}

	if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
		s.cache.Set(domain, q.Qtype, resp.Copy())
	}

	return
}
