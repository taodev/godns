// copy from AdGuard DNS
// https://github.com/AdguardTeam/dnsproxy/blob/master/internal/dnsmsg/constructor.go
package utils

import (
	"strings"

	"github.com/miekg/dns"
)

func NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return reply(req, dns.RcodeNameError)
}

func NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return reply(req, dns.RcodeServerFailure)
}

func NewMsgNOTIMPLEMENTED(req *dns.Msg) (resp *dns.Msg) {
	resp = reply(req, dns.RcodeNotImplemented)

	// Most of the Internet and especially the inner core has an MTU of at least
	// 1500 octets.  Maximum DNS/UDP payload size for IPv6 on MTU 1500 ethernet
	// is 1452 (1500 minus 40 (IPv6 header size) minus 8 (UDP header size)).
	//
	// See appendix A of https://datatracker.ietf.org/doc/draft-ietf-dnsop-avoid-fragmentation/17.
	const maxUDPPayload = 1452

	// NOTIMPLEMENTED without EDNS is treated as 'we don't support EDNS', so
	// explicitly set it.
	resp.SetEdns0(maxUDPPayload, false)

	return resp
}

func NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	resp = reply(req, dns.RcodeSuccess)

	zone := req.Question[0].Name
	soa := &dns.SOA{
		// Values copied from verisign's nonexistent .com domain.
		//
		// Their exact values are not important in our use case because they are
		// used for domain transfers between primary/secondary DNS servers.
		Refresh: 1800,
		Retry:   60,
		Expire:  604800,
		Minttl:  86400,
		// copied from AdGuard DNS
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		Mbox:   "hostmaster.",
		// rest is request-specific
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Ttl:    10,
			Class:  dns.ClassINET,
		},
	}

	if !strings.HasPrefix(zone, ".") {
		soa.Mbox += zone
	}

	resp.Ns = append(resp.Ns, soa)

	return resp
}
func reply(req *dns.Msg, code int) (resp *dns.Msg) {
	resp = new(dns.Msg)
	resp.SetRcode(req, code)
	return
}
