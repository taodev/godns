package godns

import (
	"log"
	"log/slog"

	"github.com/miekg/dns"
)

func (s *DnsServer) setupUdpServer() error {
	dns.HandleFunc(".", s.handle("udp"))
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

func (s *DnsServer) setupTcpServer() error {
	dns.HandleFunc(".", s.handle("tcp"))
	s.tcpServer = &dns.Server{
		Addr: s.Options.UDP,
		Net:  "tcp",
	}

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Printf("tcp server listen and serve failed, err: %v", err)
			s.Close()
		}
	}()

	slog.Info("dns server tcp listen", "addr", s.Options.UDP)

	return nil
}

func (s *DnsServer) handle(inbound string) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			dns.HandleFailed(w, r)
			return
		}
		ri := NewRequestInfoFromUDP(w.RemoteAddr().String())
		ri.Inbound = inbound
		resp, _, err := s.exchange(ri, r)
		if err != nil {
			dns.HandleFailed(w, r)
			return
		}
		if err := w.WriteMsg(resp); err != nil {
			slog.Error("dns response write failed", "err", err)
		}
	}
}
