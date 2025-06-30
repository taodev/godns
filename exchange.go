package godns

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *DnsServer) exchange(ri *RequestInfo, in *dns.Msg) (*dns.Msg, time.Duration, error) {
	now := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(in)
	resp.RecursionAvailable = true
	var anySuccess bool

	// 多域名请求处理
	for _, q := range in.Question {
		// 构造单独请求
		singleReq := new(dns.Msg)
		singleReq.SetQuestion(q.Name, q.Qtype)
		singleReq.RecursionDesired = in.RecursionDesired
		reply, _, err := s.exchangeSingle(ri, singleReq)
		if err != nil {
			slog.Warn("dns client exchange failed", "err", err, "question", q.Name)
			continue
		}
		if len(reply.Answer) > 0 || len(reply.Ns) > 0 || len(reply.Extra) > 0 {
			anySuccess = true
		}

		resp.Answer = append(resp.Answer, reply.Answer...)
		resp.Ns = append(resp.Ns, reply.Ns...)
		resp.Extra = append(resp.Extra, reply.Extra...)
	}

	var err error
	if anySuccess {
		resp.Rcode = dns.RcodeSuccess
	} else {
		resp.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("no valid answers for any question")
	}

	return resp, time.Since(now), err
}

func (s *DnsServer) exchangeSingle(ri *RequestInfo, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	now := time.Now()

	// 移除末尾的.
	q := r.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	// 阻止 AAAA 查询（IPv6）
	if s.Options.BlockAAAA && q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.RecursionAvailable = true
		resp.Rcode = dns.RcodeNameError // 或 NOERROR + 空答案
		resp.Answer = nil               // 不返回任何 AAAA 记录
		slog.Debug("blocked AAAA query", "domain", domain, "client", ri.IP)
		return resp, time.Since(now), nil
	}

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
