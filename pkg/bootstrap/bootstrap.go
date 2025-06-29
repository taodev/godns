package bootstrap

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	bootstrapDNS = []string{
		"223.5.5.5:53",
		"223.6.6.6:53",
	}
)

func SetDNS(dns []string) (err error) {
	if len(dns) == 0 {
		return fmt.Errorf("bootstrap: empty dns server")
	}

	var dnsList []string
	for i, addr := range dns {
		if addr == "" {
			return fmt.Errorf("bootstrap: dns[%d] is empty", i)
		}
		if strings.Contains(addr, "://") {
			return fmt.Errorf("bootstrap: dns[%d] is invalid dns: %s", i, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// 若用户未加端口，尝试补 ":53"
			addr = net.JoinHostPort(addr, "53")
			host, port, err = net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("bootstrap: dns[%d] is invalid dns: %s", i, addr)
			}
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("bootstrap: dns[%d] is invalid dns: %s", i, addr)
		}
		dnsList = append(dnsList, net.JoinHostPort(host, port))
	}
	bootstrapDNS = dnsList
	return
}

func Resolve(domain string) (string, error) {
	for _, v := range bootstrapDNS {
		c := &dns.Client{
			Net:     "udp",
			Timeout: time.Second, // 最长 1 秒
		}
		m := &dns.Msg{}
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		r, _, err := c.Exchange(m, v)
		if err != nil {
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, a := range r.Answer {
			if a, ok := a.(*dns.A); ok {
				return a.A.String(), nil
			}
		}
	}
	return "", fmt.Errorf("bootstrap: no A record found for %s", domain)
}
