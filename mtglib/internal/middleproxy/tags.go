// Package middleproxy implements the client side of Telegram's MTProto middle
// proxy (RPC) protocol. It is used to carry a client's traffic through a
// Telegram middle proxy while advertising a 16-byte ad_tag, which makes a
// sponsored channel appear in the client. The wire protocol constants and
// layouts are ported byte-for-byte from 9seconds/mtg v1 (the last mtg version
// that shipped middle-proxy support) and cross-checked against Telegram's
// official mtproto-proxy.
package middleproxy

// RPC message tags. Each is a 4-byte little-endian magic written verbatim on
// the wire.
var (
	tagNonce        = []byte{0xaa, 0x87, 0xcb, 0x7a}
	tagHandshake    = []byte{0xf5, 0xee, 0x82, 0x76}
	tagProxyRequest = []byte{0xee, 0xf1, 0xce, 0x36}
	tagProxyAns     = []byte{0x0d, 0xda, 0x03, 0x44}
	tagSimpleAck    = []byte{0x9b, 0x40, 0xac, 0x3b}
	tagCloseExt     = []byte{0xa2, 0x34, 0xb6, 0x5e}

	nonceCryptoAES = []byte{0x01, 0x00, 0x00, 0x00}
	handshakeFlags = []byte{0x00, 0x00, 0x00, 0x00}

	// proxyRequestExtraSize is the size (24 = 0x18) of the trailing TL "extra"
	// block that carries the ad_tag inside an RPC_PROXY_REQ.
	proxyRequestExtraSize = []byte{0x18, 0x00, 0x00, 0x00}

	// proxyRequestProxyTag is the TL id of the %Server_Proxy_Tag constructor
	// that precedes the ad_tag bytes.
	proxyRequestProxyTag = []byte{0xae, 0x26, 0x1e, 0xdb}

	// handshakePID is the fixed sender/peer process id used in RPC_HANDSHAKE.
	handshakePID = []byte("IPIPPRPDTIME")
)

// RPC_PROXY_REQ flag bits.
const (
	flagHasAdTag     uint32 = 0x8
	flagEncrypted    uint32 = 0x2
	flagMagic        uint32 = 0x1000
	flagExtMode2     uint32 = 0x20000
	flagIntermediate uint32 = 0x20000000
	flagQuickAck     uint32 = 0x80000000
	flagPad          uint32 = 0x8000000
)

// Frame sequence numbers with special meaning: the nonce exchange starts at -2,
// and once the AES-CBC cipher is active a fresh frame layer restarts at -1
// (handshake), after which proxy requests increment 0, 1, 2, ...
const (
	seqNoNonce     int32 = -2
	seqNoHandshake int32 = -1
)

// adTagLength is the length of a Telegram ad_tag. It mirrors mtglib.AdTagLength
// but is redeclared here to keep this internal package dependency-free.
const adTagLength = 16
