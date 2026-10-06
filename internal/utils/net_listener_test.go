package utils_test

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/internal/utils"
	"github.com/stretchr/testify/suite"
)

type MultiListenerTestSuite struct {
	suite.Suite
}

func (suite *MultiListenerTestSuite) TestAcceptFromMultipleListeners() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l1.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l2.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	for range 2 {
		conn, err := ml.Accept()
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}

	wg.Wait()
}

func (suite *MultiListenerTestSuite) TestSingleListener() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l)
	defer ml.Close() //nolint: errcheck

	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	conn, err := ml.Accept()
	suite.NoError(err)

	conn.Close() //nolint: errcheck
}

func (suite *MultiListenerTestSuite) TestCloseStopsAccept() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)

	errCh := make(chan error, 1)

	go func() {
		_, err := ml.Accept()
		errCh <- err
	}()

	suite.NoError(ml.Close())
	suite.Error(<-errCh)
}

func (suite *MultiListenerTestSuite) TestConcurrentAccept() {
	const numListeners = 3
	const connsPerListener = 10

	listeners := make([]net.Listener, numListeners)

	for i := range numListeners {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		suite.Require().NoError(err)

		listeners[i] = l
	}

	ml := utils.NewMultiListener(listeners...)
	defer ml.Close() //nolint: errcheck

	var accepted atomic.Int32

	go func() {
		for range numListeners * connsPerListener {
			conn, err := ml.Accept()
			if err != nil {
				return
			}

			accepted.Add(1)

			conn.Close() //nolint: errcheck
		}
	}()

	var wg sync.WaitGroup

	for _, l := range listeners {
		for range connsPerListener {

			wg.Go(func() {

				conn, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					return
				}

				conn.Close() //nolint: errcheck
			})
		}
	}

	wg.Wait()

	suite.Eventually(func() bool {
		return accepted.Load() == numListeners*connsPerListener
	}, 2_000_000_000, 10_000_000) // 2s timeout, 10ms poll
}

func (suite *MultiListenerTestSuite) TestAddr() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	suite.Equal(l1.Addr(), ml.Addr())
}

// flakyListener returns one temporary error and then delegates to a real
// listener.
type flakyListener struct {
	net.Listener

	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, syscall.EMFILE
	}

	return l.Listener.Accept()
}

// A temporary error on one listener must not stop accepting on it forever.
func (suite *MultiListenerTestSuite) TestTemporaryErrorDoesNotStopListener() {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(&flakyListener{Listener: base})
	defer ml.Close() //nolint: errcheck

	_, err = ml.Accept()
	suite.True(errors.Is(err, syscall.EMFILE))

	go func() {
		conn, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			conn.Close() //nolint: errcheck
		}
	}()

	accepted := make(chan error, 1)

	go func() {
		conn, err := ml.Accept()
		if err == nil {
			conn.Close() //nolint: errcheck
		}

		accepted <- err
	}()

	select {
	case err := <-accepted:
		suite.NoError(err)
	case <-time.After(2 * time.Second):
		suite.Fail("listener stopped accepting after a temporary error")
	}
}

func TestMultiListener(t *testing.T) {
	t.Parallel()
	suite.Run(t, &MultiListenerTestSuite{})
}

// firstConnBroken returns an already closed TCP connection first (setting
// socket options on it fails) and then real connections.
type firstConnBroken struct {
	net.Listener

	done atomic.Bool
}

func (l *firstConnBroken) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if l.done.CompareAndSwap(false, true) {
		conn.Close() //nolint: errcheck
	}

	return conn, nil
}

// One connection whose socket options cannot be set (for example, reset by
// the client right away) must be skipped, not stop the whole accept loop.
func TestListenerSkipsConnectionWithBrokenSocket(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	listener := utils.Listener{Listener: &firstConnBroken{Listener: base}}
	defer listener.Close() //nolint: errcheck

	for range 2 {
		go func() {
			conn, err := net.Dial("tcp", base.Addr().String())
			if err == nil {
				time.Sleep(200 * time.Millisecond)
				conn.Close() //nolint: errcheck
			}
		}()
	}

	result := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close() //nolint: errcheck
		}

		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("expected the second connection, got error %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return the next connection")
	}
}
