package godns

import (
	"log"
	"log/slog"

	"github.com/miekg/dns"
)

func (s *DnsServer) setupUdpServer() error {
	dns.HandleFunc(".", s.udpHandle)
	s.udpServer = &dns.Server{
		Addr: s.Options.UDP,
		Net:  "udp",
	}

	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil {
			log.Printf("dns server listen and serve failed, err: %v", err)
			s.Close()
		}
	}()

	slog.Info("dns server udp listen", "addr", s.Options.UDP)

	return nil
}

func (s *DnsServer) udpHandle(w dns.ResponseWriter, r *dns.Msg) {
	upstream, resp, ttl, err := s.Exchange(r)
	if err != nil {
		slog.Error("dns client exchange failed", "err", err)
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		slog.Warn("dns doh response failed", "rcode", resp.Rcode)
	}

	if err := w.WriteMsg(resp); err != nil {
		slog.Error("dns response write failed", "err", err)
	}

	for _, q := range resp.Question {
		slog.Info("dns", "rcode", resp.Rcode, "ttl", ttl, "upstream", upstream, "question", q.Name)
	}
}
