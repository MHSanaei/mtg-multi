//go:build !mips && !mipsle

package relay

import "github.com/mhsanaei/mtg-multi/mtglib/internal/tls"

const (
	bufPoolSize = tls.MaxRecordPayloadSize
)
