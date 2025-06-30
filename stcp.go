package godns

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/bytedance/gopkg/lang/mcache"
	"github.com/miekg/dns"
	"github.com/taodev/stcp"
)

type StcpServer struct {
	addr     string
	password string
	listener net.Listener
	handler  func(conn net.Conn)
}

func (svr *StcpServer) ListenAndServe() (err error) {
	svr.listener, err = stcp.Listen("tcp", svr.addr, &stcp.Config{
		Password: svr.password,
	})
	if err != nil {
		return err
	}
	for {
		conn, err := svr.listener.Accept()
		if err != nil {
			break
		}
		go func(conn net.Conn) {
			if err = conn.(*stcp.Conn).Handshake(); err != nil {
				conn.Close()
				return
			}
			if svr.handler != nil {
				svr.handler(conn)
			}
		}(conn)
	}
	return nil
}

func (svr *StcpServer) Shutdown() error {
	if svr.listener == nil {
		return fmt.Errorf("stcp server not running")
	}
	return svr.listener.Close()
}

func (svr *DnsServer) setupStcpServer() (err error) {
	svr.stcpServer = &StcpServer{
		addr:     svr.Options.STCP.Addr,
		password: svr.Options.STCP.Password,
		handler:  svr.handleStcp,
	}
	go func() {
		if err = svr.stcpServer.ListenAndServe(); err != nil {
			slog.Error("stcp server listen failed", "err", err)
		}
	}()
	slog.Info("stcp server tcp listen", "addr", svr.Options.STCP.Addr)
	return nil
}

func stcpHandleFailed(w io.Writer, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	// does not matter if this write fails
	reply, err := m.Pack()
	if err != nil {
		slog.Error("stcp handle failed pack response", "err", err)
		return
	}
	if _, err := w.Write(reply); err != nil {
		slog.Error("stcp handle failed write response", "err", err)
		return
	}
}

func stcpRead(conn net.Conn) (m *dns.Msg, err error) {
	var bufHead [2]byte
	if _, err = io.ReadFull(conn, bufHead[:]); err != nil {
		err = fmt.Errorf("stcp read header failed: %w", err)
		return
	}
	n := binary.BigEndian.Uint16(bufHead[:])
	buf := mcache.Malloc(int(n))
	defer mcache.Free(buf)
	if _, err = io.ReadFull(conn, buf); err != nil {
		err = fmt.Errorf("stcp read body failed: %w", err)
		return
	}

	m = new(dns.Msg)
	if err = m.Unpack(buf); err != nil {
		err = fmt.Errorf("stcp unpack message failed: %w", err)
		return
	}
	if len(m.Question) == 0 {
		err = fmt.Errorf("stcp message question is empty")
		return
	}
	return
}

func stcpWrite(conn net.Conn, m *dns.Msg) error {
	out, err := m.Pack()
	if err != nil {
		return fmt.Errorf("stcp pack message failed: %w", err)
	}
	buf := mcache.Malloc(len(out) + 2)
	defer mcache.Free(buf)
	binary.BigEndian.PutUint16(buf, uint16(len(out)))
	copy(buf[2:], out)
	if _, err = conn.Write(buf); err != nil {
		return fmt.Errorf("stcp write response failed: %w", err)
	}
	return nil
}

func (svr *DnsServer) handleStcp(conn net.Conn) {
	defer conn.Close()

	m, err := stcpRead(conn)
	if err != nil {
		stcpHandleFailed(conn, m)
		return
	}
	ri := NewRequestInfoFromAddr(conn.RemoteAddr().String(), "stcp")
	resp, _, err := svr.exchange(ri, m)
	if err != nil {
		stcpHandleFailed(conn, m)
		return
	}
	if err := stcpWrite(conn, resp); err != nil {
		stcpHandleFailed(conn, m)
		return
	}
}
