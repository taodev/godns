package route

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/pkg/geodb"
)

type Options struct {
	// 是否阻止 AAAA 查询（IPv6）
	BlockAAAA bool `yaml:"block-aaaa"`
	// 路由规则
	Rules []string `yaml:"rules"`
	// 默认上游
	Default string `yaml:"default"`
}

type Router struct {
	options  *Options
	rules    []*geodb.Rule
	outbound adapter.OutboundManager
	endpoint adapter.Outbound
	rewriter *rewrite.Rewriter
}

func NewRouter(options *Options, outbound adapter.OutboundManager, rewriter *rewrite.Rewriter) (*Router, error) {
	router := &Router{
		options:  options,
		rules:    make([]*geodb.Rule, 0),
		outbound: outbound,
		rewriter: rewriter,
	}
	router.endpoint, _ = outbound.Get(options.Default)
	for _, opt := range options.Rules {
		matcher, err := geodb.LoadRule(opt)
		if err != nil {
			return nil, err
		}
		out, ok := outbound.Get(matcher.Action)
		if !ok {
			return nil, fmt.Errorf("outbound %s not found for rule %s", matcher.Action, opt)
		}
		router.rules = append(router.rules, matcher)
		if router.endpoint == nil && len(router.options.Default) <= 0 {
			router.endpoint = out
		}
	}
	if router.endpoint == nil {
		return nil, fmt.Errorf("default outbound %s not found", router.options.Default)
	}
	return router, nil
}

func (r *Router) Exchange(request *dns.Msg, inbound string, ip string) (resp *dns.Msg, err error) {
	if resp := r.validateRequest(request); resp != nil {
		return resp, nil
	}
	q := request.Question[0]
	// 检查是否需要重写
	if rewrite := r.rewrite(request); rewrite != nil {
		slog.Info("request", "upstream", "rewrite", "domain", q.Name, "qtype", dns.TypeToString[q.Qtype], "inbound", inbound, "client", ip)
		return rewrite, nil
	}

	outbound := r.Route(q.Name)
	if outbound == nil {
		return utils.NewMsgSERVFAIL(request), nil
	}
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)
	req.RecursionDesired = true
	if resp, _, err = outbound.Exchange(req); err != nil {
		return utils.NewMsgSERVFAIL(request), err
	}
	// 递归查询结果判断
	if r.shouldRecurse(resp, q.Qtype) {
		return utils.NewMsgNXDOMAIN(request), nil
	}
	var answer []dns.RR
	for _, rr := range resp.Answer {
		// 判断是否禁止 AAAA
		if !r.options.BlockAAAA || rr.Header().Rrtype != dns.TypeAAAA {
			answer = append(answer, rr)
		}
		resp.Answer = answer
	}
	resp.SetReply(request)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Id = request.Id
	r.rewriter.UpdateTTL(resp)
	slog.Info("route", "qtype", dns.TypeToString[q.Qtype], "domain", q.Name, "outbound", outbound.Tag(), "ip", ip)
	return resp, nil
}

func (r *Router) Route(domain string) (outbound adapter.Outbound) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range r.rules {
		if action, ok := rule.Match(&geodb.Context{Domain: domain}); ok {
			outbound, _ = r.outbound.Get(action)
			return outbound
		}
	}
	return r.endpoint
}

func (r *Router) validateRequest(request *dns.Msg) (resp *dns.Msg) {
	switch {
	case len(request.Question) == 0:
		return utils.NewMsgNXDOMAIN(request)
	case len(request.Question) != 1:
		// TODO(e.burkov):  Probably, FORMERR would be a better choice here.
		// Check out RFC.
		return utils.NewMsgSERVFAIL(request)
	case request.Question[0].Qtype == dns.TypeANY:
		// Refuse requests of type ANY (anti-DDOS measure).
		return utils.NewMsgNOTIMPLEMENTED(request)
	case request.Question[0].Qtype == dns.TypeAAAA:
		if r.options.BlockAAAA {
			return utils.NewMsgNXDOMAIN(request)
		}
	// case p.recDetector.check(d.Req):
	// 	p.logger.Debug("recursion detected", "req_question", d.Req.Question[0].Name)

	// 	return p.messages.NewMsgNXDOMAIN(d.Req)
	case r.isForbiddenARPA(request):
		return utils.NewMsgNXDOMAIN(request)
	}
	return nil
}

func (r *Router) isForbiddenARPA(req *dns.Msg) bool {
	q := req.Question[0]
	// 处理客户端反查
	if q.Qtype == dns.TypePTR {
		return true
	}
	return false
}

func (Router) shouldRecurse(msg *dns.Msg, qtype uint16) (recurse bool) {
	for _, ans := range msg.Answer {
		if ans.Header().Rrtype == qtype {
			return false // 找到目标记录，停止
		}
		if ans.Header().Rrtype == dns.TypeCNAME {
			recurse = true
		}
	}
	return recurse // 既无目标类型，也无 CNAME，可能 NXDOMAIN 或空结果
}

func (r *Router) rewrite(req *dns.Msg) *dns.Msg {
	if rewrite, ok := r.rewriter.Rewrite(req.Question[0].Name, req.Question[0].Qtype); ok {
		rewrite.SetReply(req)
		rewrite.Authoritative = true
		rewrite.RecursionAvailable = true
		return rewrite
	}
	return nil
}

func (r *Router) updateTTL(msg *dns.Msg, minTTL, maxTTL time.Duration) {
	max := uint32(maxTTL.Seconds())
	min := uint32(minTTL.Seconds())
	for _, rr := range msg.Answer {
		if minTTL > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
		if maxTTL > 0 && rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
	for _, rr := range msg.Ns {
		if minTTL > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
	}
	for _, rr := range msg.Extra {
		if minTTL > 0 && rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
	}
}
