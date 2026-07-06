package middleproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint: gosec // required by the Telegram middle-proxy key schedule
	"crypto/sha1" //nolint: gosec // required by the Telegram middle-proxy key schedule
	"encoding/binary"
	"net"
)

type cipherPurpose uint8

const (
	purposeClient cipherPurpose = iota
	purposeServer
)

var emptyIPv4 = [4]byte{}

// deriveCiphers builds the AES-256-CBC encrypter (CLIENT purpose, our→middle)
// and decrypter (SERVER purpose, middle→our) from the exchanged nonces, the
// local/remote socket addresses and the fetched proxy secret. The exact byte
// layout and md5/sha1 mixing are the Telegram middle-proxy key schedule and
// must match the server bit-for-bit, so this is a verbatim port of
// 9seconds/mtg v1 wrappers/stream/mtproto_cipher.go.
func deriveCiphers(req *nonceRequest, resp *nonceResponse, local, remote *net.TCPAddr, secret []byte) (enc, dec cipher.BlockMode) {
	encKey, encIV := deriveKey(purposeClient, req, resp, local, remote, secret)
	decKey, decIV := deriveKey(purposeServer, req, resp, local, remote, secret)

	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		panic(err)
	}

	return cipher.NewCBCEncrypter(encBlock, encIV), cipher.NewCBCDecrypter(decBlock, decIV)
}

func deriveKey(purpose cipherPurpose, req *nonceRequest, resp *nonceResponse, client, remote *net.TCPAddr, secret []byte) (key, iv []byte) {
	message := bytes.Buffer{}

	message.Write(resp.nonce)
	message.Write(req.nonce)
	message.Write(req.cryptoTS)

	clientIPv4 := emptyIPv4[:]
	serverIPv4 := emptyIPv4[:]

	if client.IP.To4() != nil {
		clientIPv4 = reverseBytes(client.IP.To4())
		serverIPv4 = reverseBytes(remote.IP.To4())
	}

	message.Write(serverIPv4)

	var port [2]byte

	binary.LittleEndian.PutUint16(port[:], uint16(client.Port))
	message.Write(port[:])

	switch purpose {
	case purposeClient:
		message.WriteString("CLIENT")
	case purposeServer:
		message.WriteString("SERVER")
	default:
		panic("unexpected cipher purpose")
	}

	message.Write(clientIPv4)
	binary.LittleEndian.PutUint16(port[:], uint16(remote.Port))
	message.Write(port[:])
	message.Write(secret)
	message.Write(resp.nonce)

	if client.IP.To4() == nil {
		message.Write(client.IP.To16())
		message.Write(remote.IP.To16())
	}

	message.Write(req.nonce)

	data := message.Bytes()
	md5sum := md5.Sum(data[1:]) //nolint: gosec
	sha1sum := sha1.Sum(data)   //nolint: gosec

	key = append(md5sum[:12:12], sha1sum[:]...)
	ivSum := md5.Sum(data[2:]) //nolint: gosec

	return key, ivSum[:]
}

// reverseBytes returns a reversed copy of data.
func reverseBytes(data []byte) []byte {
	out := make([]byte, len(data))

	for i := range data {
		out[len(data)-1-i] = data[i]
	}

	return out
}
