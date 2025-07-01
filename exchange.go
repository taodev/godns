package godns

import (
	"log/slog"
	"time"

	"github.com/miekg/dns"
)

func (s *DnsServer) exchange(ri *RequestInfo, in *dns.Msg) (*dns.Msg, time.Duration, error) {
	now := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(in)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	// 空请求
	if len(in.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resp, time.Since(now), nil
	}

	resp.Rcode = dns.RcodeSuccess

	// 判断是否单条请求(大部分都是单条请求)
	if len(in.Question) == 1 {
		q := in.Question[0]
		// 单条请求直接处理
		reply, _, err := s.exchangeSingle(ri, in.Question[0].Qtype, in.Question[0].Name)
		if err != nil {
			slog.Debug("dns client exchange failed", "err", err, "question", in.Question[0].Name)
			return resp, time.Since(now), err
		}
		// 递归查询结果判断
		if shouldRecurse(reply, q.Qtype) {
			slog.Debug("recurse query failed", "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
		}
		for _, rr := range reply.Answer {
			// 判断是否禁止 AAAA
			if !s.Options.BlockAAAA || rr.Header().Rrtype != dns.TypeAAAA {
				resp.Answer = append(resp.Answer, rr)
			}
		}
		resp.Ns = reply.Ns
		resp.Extra = reply.Extra
		resp.Rcode = reply.Rcode
	} else {
		// 默认 Rcode（如果全部失败）
		resp.Rcode = dns.RcodeServerFailure
		// 多域名请求处理
		for _, q := range in.Question {
			// 传入初始域名，方便分流
			reply, _, err := s.exchangeSingle(ri, q.Qtype, q.Name)
			if err != nil {
				slog.Warn("dns client exchange failed", "err", err, "question", q.Name)
				continue
			}

			// 合并 Rcode 优先级（NOERROR > NXDOMAIN > SERVFAIL）
			switch reply.Rcode {
			case dns.RcodeSuccess:
				resp.Rcode = dns.RcodeSuccess
			case dns.RcodeNameError:
				if resp.Rcode != dns.RcodeSuccess {
					resp.Rcode = dns.RcodeNameError
				}
				// 其他错误维持 SERVFAIL
			}

			// 递归查询结果判断
			if shouldRecurse(reply, q.Qtype) {
				slog.Debug("recurse query failed", "domain", q.Name, "qtype", dns.TypeToString[q.Qtype])
			}

			for _, rr := range reply.Answer {
				// 判断是否禁止 AAAA
				if !s.Options.BlockAAAA || rr.Header().Rrtype != dns.TypeAAAA {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			resp.Ns = append(resp.Ns, reply.Ns...)
			resp.Extra = append(resp.Extra, reply.Extra...)
		}
	}

	return resp, time.Since(now), nil
}

func (s *DnsServer) exchangeSingle(ri *RequestInfo, qtype uint16, domain string) (*dns.Msg, time.Duration, error) {
	now := time.Now()

	// 处理客户端反查
	if qtype == dns.TypePTR {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeSuccess
		return resp, time.Since(now), nil
	}

	// 阻止 AAAA 查询（IPv6）
	if s.Options.BlockAAAA && qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		// resp.Rcode = dns.RcodeNameError // 或 NOERROR + 空答案
		resp.Answer = nil // 不返回任何 AAAA 记录
		slog.Debug("blocked AAAA query", "domain", domain, "client", ri.IP)
		return resp, time.Since(now), nil
	}

	qtypeString := dns.TypeToString[qtype]
	// 检查是否需要重写
	if rewrite, ok := s.rewrite(domain, qtype); ok {
		updateMsgTTL(rewrite, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
		rtt := time.Since(now)
		slog.Info("request", "upstream", "rewrite", "domain", domain, "qtype", qtypeString, "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)
		return rewrite, rtt, nil
	}

	// 查询缓存
	if resp, ok := s.cache.Get(domain, qtype); ok {
		cacheResp := resp.M.Copy()
		// cacheResp.Id = r.Id
		if resp.IsExpired() {
			// 异步刷新缓存
			go func(qtype uint16, domain string) {
				name := s.router.Route(domain)
				msg := new(dns.Msg)
				msg.SetQuestion(domain, qtype)
				msg.RecursionDesired = true

				refreshResp, rtt, refreshErr := s.upstream.Exchange(name, msg)
				if refreshErr != nil {
					slog.Warn("dns async refresh error", "error", refreshErr, "upstream", name, "domain", domain, "qtype", dns.TypeToString[qtype])
					return
				}
				if refreshResp.Rcode != dns.RcodeSuccess {
					slog.Warn("dns async refresh failed", "rcode", refreshResp.Rcode, "upstream", name, "domain", domain, "qtype", dns.TypeToString[qtype])
					return
				}
				updateMsgTTL(refreshResp, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
				s.cache.Set(domain, qtype, refreshResp.Copy())
				slog.Info("dns async refresh", "rcode", refreshResp.Rcode, "rtt", rtt, "upstream", name, "domain", domain, "qtype", dns.TypeToString[qtype])
			}(qtype, domain)
		}
		rtt := time.Since(now)
		slog.Info("request", "upstream", "cache", "domain", domain, "qtype", dns.TypeToString[qtype], "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)
		return cacheResp, rtt, nil
	}

	name := s.router.Route(domain)
	r := new(dns.Msg)
	r.SetQuestion(domain, qtype)
	r.RecursionDesired = true
	resp, rtt, err := s.upstream.Exchange(name, r)
	if err != nil {
		slog.Warn("dns upstream exchange error", "error", err, "upstream", name, "domain", domain, "qtype", qtypeString)
		return nil, time.Since(now), err
	}
	if resp.Rcode != dns.RcodeSuccess {
		slog.Warn("dns upstream exchange failed", "rcode", resp.Rcode, "upstream", name, "domain", domain, "qtype", qtypeString)
		return resp, time.Since(now), nil
	}

	updateMsgTTL(resp, s.Options.Cache.MinTTL, s.Options.Cache.MaxTTL)
	s.cache.Set(domain, qtype, resp.Copy())
	slog.Info("request", "upstream", name, "domain", domain, "qtype", qtypeString, "inbound", ri.Inbound, "rtt", rtt, "client", ri.IP)

	return resp, time.Since(now), nil
}
