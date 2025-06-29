package godns

import (
	"github.com/taodev/pkg/geodb"
)

type Router struct {
	Rules []*geodb.Rule
}

func (r *Router) Route(domain string) (upstream string, ok bool) {
	for _, rule := range r.Rules {
		if upstream, ok = rule.Match(&geodb.Context{Domain: domain}); ok {
			return upstream, ok
		}
	}
	return "", false
}

func NewRouter(opts []string) (*Router, error) {
	r := &Router{
		Rules: make([]*geodb.Rule, 0),
	}
	for _, opt := range opts {
		matcher, err := geodb.LoadRule(opt)
		if err != nil {
			return nil, err
		}
		r.Rules = append(r.Rules, matcher)
	}
	return r, nil
}
