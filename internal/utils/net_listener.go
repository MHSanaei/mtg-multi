package utils

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/mhsanaei/mtg-multi/network"
)

type Listener struct {
	net.Listener
}

// Accept returns the next connection with client socket options applied. A
// connection whose options cannot be set (typically it was reset by the client
// right after the handshake) is closed and skipped: returning an error here
// would stop the whole accept loop because of one bad client.
func (l Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err //nolint: wrapcheck
		}

		if err := network.SetClientSocketOptions(conn, 0); err != nil {
			conn.Close() //nolint: errcheck

			continue
		}

		return conn, nil
	}
}

func NewListener(bindTo string, bufferSize int) (net.Listener, error) {
	base, err := net.Listen("tcp", bindTo)
	if err != nil {
		return nil, fmt.Errorf("cannot build a base listener: %w", err)
	}

	return Listener{
		Listener: base,
	}, nil
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// MultiListener fans-in Accept calls from multiple underlying listeners.
type MultiListener struct {
	listeners []net.Listener
	connCh    chan acceptResult
}

func NewMultiListener(listeners ...net.Listener) *MultiListener {
	ml := &MultiListener{
		listeners: listeners,
		connCh:    make(chan acceptResult, len(listeners)),
	}

	for _, l := range listeners {
		go ml.acceptLoop(l)
	}

	return ml
}

// acceptLoop forwards connections and errors from one listener. It stops only
// when the listener is closed: a temporary error (for example, out of file
// descriptors) must not silently stop accepting on this listener forever.
func (ml *MultiListener) acceptLoop(l net.Listener) {
	var delay time.Duration

	for {
		conn, err := l.Accept()
		ml.connCh <- acceptResult{conn: conn, err: err}

		switch {
		case err == nil:
			delay = 0
		case errors.Is(err, net.ErrClosed):
			return
		default:
			delay = mtglib.AcceptRetryDelay(delay)
			time.Sleep(delay)
		}
	}
}

func (ml *MultiListener) Accept() (net.Conn, error) {
	r := <-ml.connCh
	return r.conn, r.err
}

func (ml *MultiListener) Close() error {
	var firstErr error

	for _, l := range ml.listeners {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func (ml *MultiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}
