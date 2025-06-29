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

	upstream, resp, ttl, err := s.Exchange(&req)
	if err != nil {
		http.Error(w, "exchange failed", http.StatusInternalServerError)
		return
	}

	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(out)

	for _, q := range resp.Question {
		slog.Info("dns", "rcode", resp.Rcode, "ttl", ttl, "upstream", upstream, "question", q.Name)
	}
}
