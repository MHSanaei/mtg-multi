package middleproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
)

const quickAckLength uint32 = 0x80000000

type proxyResponseType uint8

const (
	respAns proxyResponseType = iota
	respSimpleAck
	respCloseExt
)

// middleConn adapts a middle-proxy RPC channel to essentials.Conn so the
// existing byte-transparent relay can drive it unchanged. Bytes written to it
// are the client's padded-intermediate stream (client -> telegram): each
// complete inner packet is repackaged as an RPC_PROXY_REQ carrying the ad_tag.
// Bytes read from it (telegram -> client) are RPC_PROXY_ANS payloads reframed
// as padded-intermediate packets. All framing is internal, so the relay only
// ever sees a plain byte stream.
type middleConn struct {
	raw        essentials.Conn
	frame      *frameConn
	connID     [8]byte
	adTag      [adTagLength]byte
	clientAddr *net.TCPAddr
	ourAddr    *net.TCPAddr

	inbuf  []byte
	outbuf []byte
}

func newMiddleConn(raw essentials.Conn, frame *frameConn, connID [8]byte, adTag [adTagLength]byte, clientAddr, ourAddr *net.TCPAddr) *middleConn {
	return &middleConn{
		raw:        raw,
		frame:      frame,
		connID:     connID,
		adTag:      adTag,
		clientAddr: clientAddr,
		ourAddr:    ourAddr,
	}
}

func (m *middleConn) Write(p []byte) (int, error) {
	m.inbuf = append(m.inbuf, p...)

	for {
		if len(m.inbuf) < 4 {
			break
		}

		length := binary.LittleEndian.Uint32(m.inbuf[:4])

		quickAck := false
		if length >= quickAckLength {
			quickAck = true
			length -= quickAckLength
		}

		if uint64(len(m.inbuf)) < uint64(length)+4 {
			break
		}

		packet := m.inbuf[4 : 4+length]
		// Secure (padded-intermediate) frames carry 0-3 random padding bytes;
		// strip them back to the 4-byte-aligned inner packet.
		packet = packet[:len(packet)-len(packet)%4]

		if err := m.frame.writePacket(m.buildProxyReq(packet, quickAck)); err != nil {
			return 0, err
		}

		m.inbuf = m.inbuf[4+length:]
	}

	return len(p), nil
}

func (m *middleConn) Read(dst []byte) (int, error) {
	for len(m.outbuf) == 0 {
		msg, err := m.frame.readPacket()
		if err != nil {
			return 0, err
		}

		typ, payload, err := parseProxyResponse(msg)
		if err != nil {
			return 0, err
		}

		switch typ {
		case respAns:
			m.outbuf = append(m.outbuf, frameIntermediate(payload)...)
		case respSimpleAck:
			// A quick-ack is forwarded to the client verbatim, without an
			// intermediate length prefix.
			m.outbuf = append(m.outbuf, payload...)
		case respCloseExt:
			return 0, io.EOF
		}
	}

	n := copy(dst, m.outbuf)
	m.outbuf = m.outbuf[n:]

	return n, nil
}

func (m *middleConn) buildProxyReq(packet []byte, quickAck bool) []byte {
	flags := flagHasAdTag | flagMagic | flagExtMode2 | flagIntermediate | flagPad

	if quickAck {
		flags |= flagQuickAck
	}

	if len(packet) >= 8 && isAllZero(packet[:8]) {
		flags |= flagEncrypted
	}

	buf := &bytes.Buffer{}

	buf.Write(tagProxyRequest)
	binary.Write(buf, binary.LittleEndian, flags) //nolint: errcheck
	buf.Write(m.connID[:])
	buf.Write(encodeIPPort(m.clientAddr))
	buf.Write(encodeIPPort(m.ourAddr))
	buf.Write(proxyRequestExtraSize)
	buf.Write(proxyRequestProxyTag)
	buf.WriteByte(byte(len(m.adTag)))
	buf.Write(m.adTag[:])

	if pad := (4 - buf.Len()%4) % 4; pad > 0 {
		buf.Write(make([]byte, pad))
	}

	buf.Write(packet)

	return buf.Bytes()
}

func (m *middleConn) Close() error                       { return m.raw.Close() }
func (m *middleConn) CloseRead() error                   { return m.raw.CloseRead() }
func (m *middleConn) CloseWrite() error                  { return m.raw.CloseWrite() }
func (m *middleConn) LocalAddr() net.Addr                { return m.raw.LocalAddr() }
func (m *middleConn) RemoteAddr() net.Addr               { return m.raw.RemoteAddr() }
func (m *middleConn) SetDeadline(t time.Time) error      { return m.raw.SetDeadline(t) }
func (m *middleConn) SetReadDeadline(t time.Time) error  { return m.raw.SetReadDeadline(t) }
func (m *middleConn) SetWriteDeadline(t time.Time) error { return m.raw.SetWriteDeadline(t) }

// parseProxyResponse classifies an RPC response and returns its client-bound
// payload. Layouts: RPC_PROXY_ANS = tag(4)|flags(4)|conn_id(8)|payload;
// RPC_SIMPLE_ACK = tag(4)|conn_id(8)|payload; RPC_CLOSE_EXT = tag(4).
func parseProxyResponse(packet []byte) (proxyResponseType, []byte, error) {
	if len(packet) < 4 {
		return 0, nil, io.ErrUnexpectedEOF
	}

	tag := packet[:4]

	switch {
	case bytes.Equal(tag, tagProxyAns):
		if len(packet) < 16 {
			return 0, nil, io.ErrUnexpectedEOF
		}

		return respAns, packet[16:], nil
	case bytes.Equal(tag, tagSimpleAck):
		if len(packet) < 12 {
			return 0, nil, io.ErrUnexpectedEOF
		}

		return respSimpleAck, packet[12:], nil
	case bytes.Equal(tag, tagCloseExt):
		return respCloseExt, nil, nil
	}

	return 0, nil, io.ErrUnexpectedEOF
}

// frameIntermediate wraps payload as a padded-intermediate packet for the
// client: a 4-byte little-endian length followed by the payload. No random
// padding is added; the outer obfuscated2/faketls layers already randomize the
// stream.
func frameIntermediate(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)

	return out
}

// encodeIPPort serializes addr as 16 bytes of IPv6-mapped address followed by a
// 4-byte little-endian port, as expected inside RPC_PROXY_REQ.
func encodeIPPort(addr *net.TCPAddr) []byte {
	out := make([]byte, 20)

	if addr != nil {
		copy(out[:16], addr.IP.To16())
		binary.LittleEndian.PutUint32(out[16:], uint32(addr.Port))
	}

	return out
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}

	return true
}
