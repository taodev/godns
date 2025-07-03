package tcp

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/bytedance/gopkg/lang/mcache"
	"github.com/miekg/dns"
)

func read(conn net.Conn) (req *dns.Msg, err error) {
	var length uint16
	buf := mcache.Malloc(2 + dns.MaxMsgSize)
	defer mcache.Free(buf)
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	if length = binary.BigEndian.Uint16(buf[:2]); length == 0 || length > dns.MaxMsgSize {
		return nil, err
	}
	if _, err = io.ReadFull(conn, buf[:length]); err != nil {
		return nil, err
	}

	req = new(dns.Msg)
	if err = req.Unpack(buf[:length]); err != nil {
		return nil, err
	}
	return req, nil
}

func write(conn net.Conn, m *dns.Msg) (err error) {
	bytes, err := m.Pack()
	if err != nil {
		return err
	}
	buf := mcache.Malloc(2 + dns.MaxMsgSize)
	defer mcache.Free(buf)
	binary.BigEndian.PutUint16(buf, uint16(len(bytes)))
	n := copy(buf[2:], bytes)
	_, err = conn.Write(buf[:2+n])
	return err
}

func failed(conn net.Conn, req *dns.Msg, rcode int) (err error) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return write(conn, m)
}
