package middleproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
)

type nonceRequest struct {
	keySelector []byte
	cryptoTS    []byte
	nonce       []byte
}

func newNonceRequest(proxySecret []byte) (*nonceRequest, error) {
	nonce := make([]byte, 16)
	keySelector := make([]byte, 4)
	cryptoTS := make([]byte, 4)

	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot generate nonce: %w", err)
	}

	copy(keySelector, proxySecret)

	timestamp := time.Now().Truncate(time.Second).Unix() % 4294967296
	binary.LittleEndian.PutUint32(cryptoTS, uint32(timestamp))

	return &nonceRequest{keySelector: keySelector, cryptoTS: cryptoTS, nonce: nonce}, nil
}

func (r *nonceRequest) bytes() []byte {
	buf := &bytes.Buffer{}

	buf.Write(tagNonce)
	buf.Write(r.keySelector)
	buf.Write(nonceCryptoAES)
	buf.Write(r.cryptoTS)
	buf.Write(r.nonce)

	return buf.Bytes()
}

type nonceResponse struct {
	nonce []byte
}

func parseNonceResponse(data []byte, req *nonceRequest) (*nonceResponse, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("unexpected nonce response length %d", len(data))
	}

	if !bytes.Equal(data[:4], tagNonce) {
		return nil, fmt.Errorf("unexpected nonce response tag %x", data[:4])
	}

	if !bytes.Equal(data[8:12], nonceCryptoAES) {
		return nil, fmt.Errorf("unexpected crypto type %x", data[8:12])
	}

	if !bytes.Equal(data[4:8], req.keySelector) {
		return nil, fmt.Errorf("unexpected key selector %x", data[4:8])
	}

	return &nonceResponse{nonce: data[16:]}, nil
}

func handshakeRequestBytes() []byte {
	buf := &bytes.Buffer{}

	buf.Write(tagHandshake)
	buf.Write(handshakeFlags)
	buf.Write(handshakePID)
	buf.Write(handshakePID)

	return buf.Bytes()
}

func validateHandshakeResponse(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("incorrect handshake response length %d", len(data))
	}

	if !bytes.Equal(data[:4], tagHandshake) {
		return fmt.Errorf("unexpected handshake tag %x", data[:4])
	}

	if !bytes.Equal(data[20:], handshakePID) {
		return fmt.Errorf("incorrect peer PID %x", data[20:])
	}

	return nil
}

// doHandshake performs the RPC nonce and handshake exchange over conn and
// returns the framed, AES-256-CBC-encrypted channel that carries subsequent
// RPC_PROXY_REQ/RPC_PROXY_ANS traffic. local and remote are the addresses fed
// to the key schedule (local may be overridden with the proxy's public IP).
func doHandshake(conn essentials.Conn, secret []byte, local, remote *net.TCPAddr) (*frameConn, error) {
	req, err := newNonceRequest(secret)
	if err != nil {
		return nil, err
	}

	rawFrame := newFrameConn(conn, seqNoNonce)
	if err := rawFrame.writePacket(req.bytes()); err != nil {
		return nil, fmt.Errorf("cannot send nonce request: %w", err)
	}

	respBytes, err := rawFrame.readPacket()
	if err != nil {
		return nil, fmt.Errorf("cannot read nonce response: %w", err)
	}

	resp, err := parseNonceResponse(respBytes, req)
	if err != nil {
		return nil, err
	}

	enc, dec := deriveCiphers(req, resp, local, remote, secret)
	cbcFrame := newFrameConn(newCBCConn(conn, enc, dec), seqNoHandshake)

	if err := cbcFrame.writePacket(handshakeRequestBytes()); err != nil {
		return nil, fmt.Errorf("cannot send handshake request: %w", err)
	}

	hsBytes, err := cbcFrame.readPacket()
	if err != nil {
		return nil, fmt.Errorf("cannot read handshake response: %w", err)
	}

	if err := validateHandshakeResponse(hsBytes); err != nil {
		return nil, err
	}

	return cbcFrame, nil
}
