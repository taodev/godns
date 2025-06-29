package godns

import (
	"io"
	"log/slog"
	"net/http"

	"github.com/miekg/dns"
)

func (s *DnsServer) setupDohServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)

	s.dohServer = &http.Server{
		Addr:    s.Options.DoH,
		Handler: mux,
	}

	go func() {
		if len(s.Options.Cert) > 0 {
			if err := s.dohServer.ListenAndServeTLS(s.Options.Cert, s.Options.Key); err != nil && err != http.ErrServerClosed {
				slog.Error("ListenAndServeTLS error", slog.Any("err", err))
				s.Close()
			}
		} else {
			if err := s.dohServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("ListenAndServe error", slog.Any("err", err))
				s.Close()
			}
		}
	}()

	slog.Info("dns server doh listen", "addr", s.Options.DoH)
	return nil
}

func (s *DnsServer) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}

	var req dns.Msg
	if err := req.Unpack(body); err != nil {
		http.Error(w, "unpack failed", http.StatusBadRequest)
		return
	}
	if req.Rcode != dns.RcodeSuccess {
		slog.Warn("dns doh response failed", "rcode", req.Rcode)
	}
	if len(req.Question) == 0 {
		http.Error(w, "no question", http.StatusBadRequest)
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.RecursionAvailable = true
	ri := NewRequestInfoFromHTTP(r)
	var anySuccess bool

	// 多域名请求处理
	for _, q := range req.Question {
		// 构造单独请求
		singleReq := new(dns.Msg)
		singleReq.SetQuestion(q.Name, q.Qtype)
		singleReq.RecursionDesired = req.RecursionDesired
		reply, _, err := s.exchange(ri, singleReq)
		if err != nil {
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

	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	if _, err = w.Write(out); err != nil {
		slog.Error("dns response write failed", "err", err)
		return
	}
}
