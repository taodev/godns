package godns

import (
	"encoding/base64"
	"fmt"
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
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if len(s.Options.Cert) > 0 {
			if err := s.dohServer.ListenAndServeTLS(s.Options.Cert, s.Options.Key); err != nil && err != http.ErrServerClosed {
				s.errorCh <- fmt.Errorf("doh server listen and serve tls failed, err: %v", err)
			}
			slog.Info("https server close")
		} else {
			if err := s.dohServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.errorCh <- fmt.Errorf("doh server listen and serve failed, err: %v", err)
			}
			slog.Info("http server close")
		}
	}()

	slog.Info("dns server doh listen", "addr", s.Options.DoH)
	return nil
}

func (s *DnsServer) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		// 必须是 POST 和 GET 方法
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	var body []byte
	var err error
	if r.Method == http.MethodPost {
		// 处理 POST 请求体
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
	} else {
		// 读取 GET 参数 `dns`（Base64URL 编码的 wire format 数据）
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		// Base64URL 解码
		body, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64url in 'dns' parameter", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/dns-message")
	var req dns.Msg
	if err := req.Unpack(body); err != nil {
		http.Error(w, "unpack failed", http.StatusBadRequest)
		return
	}
	ri := NewRequestInfoFromHTTP(r)
	resp, _, err := s.exchange(ri, &req)
	var reply []byte
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(&req, dns.RcodeServerFailure)
		if reply, err = m.Pack(); err != nil {
			slog.Warn("DoH handle failed pack response", "err", err)
		}
		if _, err = w.Write(reply); err != nil {
			slog.Debug("DoH response write failed", "err", err)
		}
		return
	}

	reply, err = resp.Pack()
	if err != nil {
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(reply); err != nil {
		slog.Debug("DoH response write failed", "err", err)
		return
	}
}
