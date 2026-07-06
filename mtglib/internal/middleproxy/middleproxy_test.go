package middleproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	frame := newFrameConn(buf, 0)

	msgs := [][]byte{
		{0xde, 0xad, 0xbe, 0xef},
		bytes.Repeat([]byte{0x11}, 40),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	for _, msg := range msgs {
		require.NoError(t, frame.writePacket(msg))
	}

	for _, want := range msgs {
		got, err := frame.readPacket()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

func TestCBCFrameRoundTrip(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x24}, 16)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	writer := newFrameConn(newCBCConn(buf, cipher.NewCBCEncrypter(block, iv), nil), seqNoHandshake)
	reader := newFrameConn(newCBCConn(buf, nil, cipher.NewCBCDecrypter(block, iv)), seqNoHandshake)

	want := bytes.Repeat([]byte{0xab, 0xcd}, 20)
	require.NoError(t, writer.writePacket(want))

	got, err := reader.readPacket()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestBuildProxyReqLayout(t *testing.T) {
	t.Parallel()

	m := &middleConn{
		connID:     [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		adTag:      [adTagLength]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		clientAddr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678},
		ourAddr:    &net.TCPAddr{IP: net.ParseIP("9.10.11.12"), Port: 443},
	}

	packet := []byte{0xde, 0xad, 0xbe, 0xef}
	got := m.buildProxyReq(packet, false)

	assert.Equal(t, tagProxyRequest, got[0:4], "tag")

	flags := binary.LittleEndian.Uint32(got[4:8])
	assert.Equal(t, flagHasAdTag|flagMagic|flagExtMode2|flagIntermediate|flagPad, flags, "flags")
	assert.Zero(t, flags&flagQuickAck, "no quick ack")
	assert.Zero(t, flags&flagEncrypted, "no encrypted flag for non-zero prefix")

	assert.Equal(t, m.connID[:], got[8:16], "conn id")

	assert.Equal(t, net.ParseIP("1.2.3.4").To16(), net.IP(got[16:32]), "client ip")
	assert.Equal(t, uint32(5678), binary.LittleEndian.Uint32(got[32:36]), "client port")

	assert.Equal(t, net.ParseIP("9.10.11.12").To16(), net.IP(got[36:52]), "our ip")
	assert.Equal(t, uint32(443), binary.LittleEndian.Uint32(got[52:56]), "our port")

	assert.Equal(t, proxyRequestExtraSize, got[56:60], "extra size")
	assert.Equal(t, proxyRequestProxyTag, got[60:64], "proxy tag")
	assert.Equal(t, byte(adTagLength), got[64], "ad tag length byte")
	assert.Equal(t, m.adTag[:], got[65:81], "ad tag")

	// 81 bytes so far -> 3 padding bytes to reach a 4-byte boundary (84),
	// then the client packet.
	assert.Equal(t, []byte{0, 0, 0}, got[81:84], "alignment padding")
	assert.Equal(t, packet, got[84:], "packet")
	assert.Zero(t, len(got[:84])%4, "packet must start on a 4-byte boundary")
}

func TestBuildProxyReqFlags(t *testing.T) {
	t.Parallel()

	m := &middleConn{
		clientAddr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1},
		ourAddr:    &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 2},
	}

	quick := m.buildProxyReq([]byte{1, 2, 3, 4}, true)
	assert.NotZero(t, binary.LittleEndian.Uint32(quick[4:8])&flagQuickAck, "quick ack flag set")

	enc := m.buildProxyReq(bytes.Repeat([]byte{0}, 12), false)
	assert.NotZero(t, binary.LittleEndian.Uint32(enc[4:8])&flagEncrypted, "encrypted flag set for zero prefix")
}

func TestParseProxyResponse(t *testing.T) {
	t.Parallel()

	ans := append(append(append([]byte{}, tagProxyAns...), make([]byte, 12)...), []byte{0x11, 0x22}...)
	typ, payload, err := parseProxyResponse(ans)
	require.NoError(t, err)
	assert.Equal(t, respAns, typ)
	assert.Equal(t, []byte{0x11, 0x22}, payload)

	ack := append(append(append([]byte{}, tagSimpleAck...), make([]byte, 8)...), []byte{0xaa, 0xbb, 0xcc, 0xdd}...)
	typ, payload, err = parseProxyResponse(ack)
	require.NoError(t, err)
	assert.Equal(t, respSimpleAck, typ)
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, payload)

	typ, _, err = parseProxyResponse(tagCloseExt)
	require.NoError(t, err)
	assert.Equal(t, respCloseExt, typ)

	_, _, err = parseProxyResponse([]byte{0x00, 0x00, 0x00, 0x00})
	assert.Error(t, err)
}

func TestNonceCodec(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{0x7}, 16)
	req, err := newNonceRequest(secret)
	require.NoError(t, err)

	raw := req.bytes()
	require.Len(t, raw, 32)
	assert.Equal(t, tagNonce, raw[0:4])
	assert.Equal(t, secret[:4], raw[4:8])
	assert.Equal(t, nonceCryptoAES, raw[8:12])

	// A well-formed response echoes the tag, key selector and crypto type.
	resp := make([]byte, 32)
	copy(resp[0:4], tagNonce)
	copy(resp[4:8], req.keySelector)
	copy(resp[8:12], nonceCryptoAES)
	copy(resp[16:], bytes.Repeat([]byte{0x9}, 16))

	parsed, err := parseNonceResponse(resp, req)
	require.NoError(t, err)
	assert.Len(t, parsed.nonce, 16)

	// A wrong key selector is rejected.
	bad := append([]byte{}, resp...)
	bad[4] ^= 0xff
	_, err = parseNonceResponse(bad, req)
	assert.Error(t, err)
}

func TestDeriveKeyShape(t *testing.T) {
	t.Parallel()

	req := &nonceRequest{
		keySelector: []byte{1, 2, 3, 4},
		cryptoTS:    []byte{5, 6, 7, 8},
		nonce:       bytes.Repeat([]byte{0x1}, 16),
	}
	resp := &nonceResponse{nonce: bytes.Repeat([]byte{0x2}, 16)}
	local := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111}
	remote := &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 2222}
	secret := bytes.Repeat([]byte{0x3}, 16)

	key, iv := deriveKey(purposeClient, req, resp, local, remote, secret)
	assert.Len(t, key, 32)
	assert.Len(t, iv, 16)

	key2, iv2 := deriveKey(purposeClient, req, resp, local, remote, secret)
	assert.Equal(t, key, key2, "derivation is deterministic")
	assert.Equal(t, iv, iv2)

	serverKey, _ := deriveKey(purposeServer, req, resp, local, remote, secret)
	assert.NotEqual(t, key, serverKey, "client and server keys differ")
}

func TestParseMiddleConfig(t *testing.T) {
	t.Parallel()

	body := `# comment
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.162.38:80;
proxy_for -2 95.161.76.100:8888;
default 2;
`
	cfg, err := parseMiddleConfig([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, []string{"149.154.175.50:8888"}, cfg[1])
	assert.Equal(t, []string{"149.154.175.50:8888"}, cfg[-1])
	assert.Equal(t, []string{"149.154.162.38:80"}, cfg[2])
	assert.Equal(t, []string{"95.161.76.100:8888"}, cfg[-2])
}

func TestReverseBytes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []byte{4, 3, 2, 1}, reverseBytes([]byte{1, 2, 3, 4}))
	assert.Equal(t, []byte{1}, reverseBytes([]byte{1}))
	assert.Empty(t, reverseBytes([]byte{}))
}
