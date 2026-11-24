package gate

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

var errGotHello = errors.New("client hello captured")

// recordingConn feeds a TLS server handshake from r while recording every
// byte read, and swallows writes so nothing reaches the client.
type recordingConn struct {
	net.Conn
	r   io.Reader
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}
func (c *recordingConn) Write(p []byte) (int, error) { return len(p), nil }

// peekSNI reads the client's TLS ClientHello from br without consuming it
// for the upstream: it returns the server name (empty if absent), whether
// the stream looked like TLS at all, and the bytes that must be replayed.
func peekSNI(conn net.Conn, br *bufio.Reader) (sni string, isTLS bool, replay []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	first, err := br.Peek(1)
	if err != nil {
		return "", false, nil, err
	}
	if first[0] != 0x16 { // not a TLS handshake record
		return "", false, nil, nil
	}
	rc := &recordingConn{Conn: conn, r: br}
	srv := tls.Server(rc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errGotHello
		},
	})
	herr := srv.Handshake()
	if !errors.Is(herr, errGotHello) {
		return "", true, rc.buf.Bytes(), errors.New("無法解析 TLS ClientHello")
	}
	return sni, true, rc.buf.Bytes(), nil
}
