package middleproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	frameMinMessageLength = 12
	frameMaxMessageLength = 16777216
)

// framePadding is the 4-byte word repeated to pad a frame up to a 16-byte
// multiple. On read, leading padding words are skipped.
var framePadding = []byte{0x04, 0x00, 0x00, 0x00}

// cbcConn wraps a raw connection with AES-256-CBC in both directions. The RPC
// transport frame guarantees every write is a whole number of 16-byte blocks;
// reads are served one decrypted block at a time so an arbitrary byte count can
// be requested by the frame reader.
type cbcConn struct {
	raw io.ReadWriter
	enc cipher.BlockMode
	dec cipher.BlockMode
	buf []byte
}

func newCBCConn(raw io.ReadWriter, enc, dec cipher.BlockMode) *cbcConn {
	return &cbcConn{raw: raw, enc: enc, dec: dec}
}

func (c *cbcConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		block := make([]byte, aes.BlockSize)

		if _, err := io.ReadFull(c.raw, block); err != nil {
			return 0, err //nolint: wrapcheck
		}

		c.dec.CryptBlocks(block, block)
		c.buf = block
	}

	n := copy(p, c.buf)
	c.buf = c.buf[n:]

	return n, nil
}

func (c *cbcConn) Write(p []byte) (int, error) {
	if len(p)%aes.BlockSize != 0 {
		return 0, fmt.Errorf("cbc write of non-block-aligned length %d", len(p))
	}

	encrypted := make([]byte, len(p))
	c.enc.CryptBlocks(encrypted, p)

	if _, err := c.raw.Write(encrypted); err != nil {
		return 0, err //nolint: wrapcheck
	}

	return len(p), nil
}

// frameConn layers the MTProto RPC transport frame over an io.ReadWriter:
//
//	[ MSGLEN(4) | SEQNO(4) | MSG(...) | CRC32(4) | PADDING(4*k) ]
//
// MSGLEN counts itself, SEQNO, MSG and CRC32; CRC32 covers MSGLEN+SEQNO+MSG;
// PADDING is 0x04000000 words repeated until the frame length is a 16-byte
// multiple. Read/write sequence numbers must match the peer's.
type frameConn struct {
	raw        io.ReadWriter
	readSeqNo  int32
	writeSeqNo int32
}

func newFrameConn(raw io.ReadWriter, seqNo int32) *frameConn {
	return &frameConn{raw: raw, readSeqNo: seqNo, writeSeqNo: seqNo}
}

func (f *frameConn) writePacket(msg []byte) error {
	messageLength := 4 + 4 + len(msg) + 4
	paddingLength := (aes.BlockSize - messageLength%aes.BlockSize) % aes.BlockSize

	buf := &bytes.Buffer{}

	binary.Write(buf, binary.LittleEndian, uint32(messageLength)) //nolint: errcheck
	binary.Write(buf, binary.LittleEndian, f.writeSeqNo)          //nolint: errcheck
	buf.Write(msg)

	checksum := crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.LittleEndian, checksum) //nolint: errcheck

	buf.Write(bytes.Repeat(framePadding, paddingLength/4))

	f.writeSeqNo++

	_, err := f.raw.Write(buf.Bytes())

	return err //nolint: wrapcheck
}

func (f *frameConn) readPacket() ([]byte, error) {
	var lenBuf [4]byte

	for {
		if _, err := io.ReadFull(f.raw, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("cannot read frame length: %w", err)
		}

		if !bytes.Equal(lenBuf[:], framePadding) {
			break
		}
	}

	messageLength := binary.LittleEndian.Uint32(lenBuf[:])
	if messageLength%4 != 0 || messageLength < frameMinMessageLength || messageLength > frameMaxMessageLength {
		return nil, fmt.Errorf("incorrect frame message length %d", messageLength)
	}

	rest := make([]byte, messageLength-4)
	if _, err := io.ReadFull(f.raw, rest); err != nil {
		return nil, fmt.Errorf("cannot read frame body: %w", err)
	}

	seqNo := int32(binary.LittleEndian.Uint32(rest[:4]))
	if seqNo != f.readSeqNo {
		return nil, fmt.Errorf("unexpected sequence number %d (want %d)", seqNo, f.readSeqNo)
	}

	msg := rest[4 : len(rest)-4]
	checksum := binary.LittleEndian.Uint32(rest[len(rest)-4:])

	sum := crc32.NewIEEE()
	sum.Write(lenBuf[:])
	sum.Write(rest[:len(rest)-4])

	if got := sum.Sum32(); got != checksum {
		return nil, fmt.Errorf("crc32 mismatch: want %d, got %d", checksum, got)
	}

	f.readSeqNo++

	return msg, nil
}
