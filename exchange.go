package godns

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *DnsServer) Exchange(r *dns.Msg) (resp *dns.Msg, err error) {
	if len(r.Question) == 0 {
		return nil, fmt.Errorf("no question")
	}

	if len(r.Question) > 1 {
		slog.Debug("multiple questions in request, only the first will be processed",
			"count", len(r.Question),
			"first", r.Question[0].Name,
			"type", dns.TypeToString[r.Question[0].Qtype],
		)
	}

	// 移除末尾的.
	q := r.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	// 查询缓存, 单条查询时才缓存
	if len(r.Question) == 1 {
		if resp, ok := s.cache.Get(domain, q.Qtype); ok {
			cacheResp := resp.M.Copy()
			cacheResp.Id = r.Id
			slog.Debug("dns hit cache", "domain", q.Name)
			return cacheResp, nil
		}
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
