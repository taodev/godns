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
	domain := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
	upstream, ok := s.router.Route(domain)
	if ok {
		resp, rtt, err = s.upstream.Exchange(upstream, r)
		return
	}

	upstream = s.upstream.defaultUpstream.Name()
	resp, rtt, err = s.upstream.defaultUpstream.Exchange(r)
	return
}
