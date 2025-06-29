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
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true
	var anySuccess bool

	if len(r.Question) > 1 {
		slog.Warn("dns udp request with multiple questions", "questions", len(r.Question))
	}

	// 多域名请求处理
	for _, q := range r.Question {
		// 构造单独请求
		singleReq := new(dns.Msg)
		singleReq.SetQuestion(q.Name, q.Qtype)
		singleReq.RecursionDesired = r.RecursionDesired
		reply, err := s.exchange(singleReq)
		if err != nil || reply == nil || reply.Rcode != dns.RcodeSuccess {
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
	if anySuccess {
		resp.Rcode = dns.RcodeSuccess
	} else {
		resp.Rcode = dns.RcodeServerFailure
	}

	if err := w.WriteMsg(resp); err != nil {
		slog.Error("dns response write failed", "err", err)
	}
}
