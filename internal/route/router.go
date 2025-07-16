package route

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/cache"
	"github.com/taodev/godns/internal/rewrite"
	"github.com/taodev/godns/internal/utils"
	"github.com/taodev/pkg/geodb"
	"github.com/taodev/pkg/util"
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
	cache    *cache.Cache
}

func New(options *Options, outbound adapter.OutboundManager, rewriter *rewrite.Rewriter, cache *cache.Cache) (*Router, error) {
	router := &Router{
		options:  options,
		rules:    make([]*geodb.Rule, 0),
		outbound: outbound,
		rewriter: rewriter,
		cache:    cache,
	}
	cache.SetQuery(router)
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

	// // 查询缓存
	cv, ok := r.cache.GetAndUpdate(q.Name, q.Qtype, ip)
	if ok {
		resp = cv.M.Copy()
		resp.SetReply(request)
		slog.Info("route", "qtype", dns.TypeToString[q.Qtype], "domain", q.Name, "inbound", inbound, "outbound", "cache", "ip", ip)
		return resp, nil
	}

	resp, outboundTag, err := r.Resolve(request, net.ParseIP(ip))
	if err != nil {
		slog.Debug("route", "qtype", dns.TypeToString[q.Qtype], "domain", q.Name, "outbound", outboundTag, "error", err)
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return resp, nil
	}

	// 缓存
	r.cache.Set(q.Name, q.Qtype, resp, ip)
	slog.Info("route", "qtype", dns.TypeToString[q.Qtype], "domain", q.Name, "inbound", inbound, "outbound", outboundTag, "ip", ip, "response", resp.Answer)
	return resp, nil
}

func (r *Router) Resolve(in *dns.Msg, ip net.IP) (resp *dns.Msg, outboundTag string, err error) {
	q := in.Question[0]
	outbound := r.Route(q.Name)
	if outbound == nil {
		return utils.NewMsgSERVFAIL(in), "", nil
	}

	in.RecursionDesired = true
	// r.processECS(in, ip)
	if resp, _, err = outbound.Exchange(in); err != nil {
		return utils.NewMsgSERVFAIL(in), "", err
	}
	var answer []dns.RR
	for _, rr := range resp.Answer {
		// 判断是否禁止 AAAA
		if !r.options.BlockAAAA || rr.Header().Rrtype != dns.TypeAAAA {
			answer = append(answer, rr)
		}
		resp.Answer = answer
	}
	resp.SetReply(in)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Id = in.Id
	r.rewriter.UpdateTTL(resp)
	return resp, outbound.Tag(), nil
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

func (r *Router) rewrite(req *dns.Msg) *dns.Msg {
	if rewrite, ok := r.rewriter.Rewrite(req.Question[0].Name, req.Question[0].Qtype); ok {
		rewrite.SetReply(req)
		rewrite.Authoritative = true
		rewrite.RecursionAvailable = true
		return rewrite
	}
	return nil
}

// processECS 添加 EDNS Client Subnet 到 DNS 请求中
func (r *Router) processECS(in *dns.Msg, cliIP net.IP) (reqECS *net.IPNet) {
	// 检查消息中是否已有有效 ECS 选项（避免覆盖）
	if ecs, _ := ecsFromMsg(in); ecs != nil {
		if ones, _ := ecs.Mask.Size(); ones != 0 {
			return ecs
		}
	}

	// 解析客户端 IP（处理 IPv4/IPv6）
	cliAddr, ok := netip.AddrFromSlice(cliIP)
	if !ok {
		slog.Debug("parse client IP failed", "ip", cliIP)
		return nil
	}

	slog.Debug("process ECS", "ip", cliIP, "cliAddr", cliAddr)
	if !util.IsSpecialPurpose(cliAddr) {
		// A Stub Resolver MUST set SCOPE PREFIX-LENGTH to 0.  See RFC 7871
		// Section 6.
		return setECS(in, cliIP, 0)
	}

	return nil
}
