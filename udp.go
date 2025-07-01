package godns

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
)

func (s *DnsServer) setupUdpServer() error {
	dns.HandleFunc(".", s.handle("udp"))
	s.udpServer = &dns.Server{
		Addr: s.Options.UDP,
		Net:  "udp",
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.udpServer.ListenAndServe(); err != nil {
			s.errorCh <- fmt.Errorf("dns server listen and serve failed, err: %v", err)
		}
		slog.Info("udp server close")
	}()

	slog.Info("udp server listen", "addr", s.Options.UDP)

	return nil
}

func (s *DnsServer) setupTcpServer() error {
	dns.HandleFunc(".", s.handle("tcp"))
	s.tcpServer = &dns.Server{
		Addr: s.Options.TCP,
		Net:  "tcp",
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.tcpServer.ListenAndServe(); err != nil {
			s.errorCh <- fmt.Errorf("tcp server listen and serve failed, err: %v", err)
		}
		slog.Debug("tcp server close")
	}()

	slog.Info("tcp server listen", "addr", s.Options.TCP)

	return nil
}

func (s *DnsServer) handle(inbound string) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		ri := NewRequestInfoFromAddr(w.RemoteAddr().String(), inbound)
		resp, _, err := s.exchange(ri, r)
		if err != nil {
			dns.HandleFailed(w, r)
			return
		}
		if err := w.WriteMsg(resp); err != nil {
			slog.Debug("dns response write failed", "client", w.RemoteAddr().String(), "err", err)
		}
	}
}
