package mtglib_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/antireplay"
	"github.com/mhsanaei/mtg-multi/events"
	"github.com/mhsanaei/mtg-multi/ipblocklist"
	"github.com/mhsanaei/mtg-multi/ipblocklist/files"
	"github.com/mhsanaei/mtg-multi/logger"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/mhsanaei/mtg-multi/network"
	"github.com/stretchr/testify/suite"
	"github.com/yl2chen/cidranger"
)

type ProxyTestSuite struct {
	suite.Suite

	opts        *mtglib.ProxyOpts
	p           *mtglib.Proxy
	listener    net.Listener
	frontServer *httptest.Server
}

func (suite *ProxyTestSuite) ProxyAddress() string {
	_, port, _ := net.SplitHostPort(suite.listener.Addr().String())

	return net.JoinHostPort("127.0.0.1", port)
}

func (suite *ProxyTestSuite) ProxySecret() string {
	return suite.opts.Secret.Hex()
}

func (suite *ProxyTestSuite) SetupSuite() {
	dialer, err := network.NewDefaultDialer(0, 0)
	suite.NoError(err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	suite.NoError(err)

	allowlist, _ := ipblocklist.NewFireholFromFiles(
		logger.NewNoopLogger(),
		1,
		[]files.File{
			files.NewMem([]*net.IPNet{
				cidranger.AllIPv4,
				cidranger.AllIPv6,
			}),
		},
		nil,
	)

	go allowlist.Run(time.Second)

	// A local stand-in for the fronting domain (httpbin.org) so the test
	// does not depend on external network availability.
	suite.frontServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]map[string]string{ //nolint: errcheck
			"headers": {"X-Amzn-Trace-Id": "Root=1-mtg-test"},
		})
	}))

	frontHost, frontPortStr, err := net.SplitHostPort(suite.frontServer.Listener.Addr().String())
	suite.Require().NoError(err)

	frontPort, err := strconv.ParseUint(frontPortStr, 10, 16)
	suite.Require().NoError(err)

	suite.opts = &mtglib.ProxyOpts{
		Secret:             mtglib.GenerateSecret("httpbin.org"),
		Network:            ntw,
		AntiReplayCache:    antireplay.NewNoop(),
		IPBlocklist:        ipblocklist.NewNoop(),
		IPAllowlist:        allowlist,
		EventStream:        events.NewNoopStream(),
		Logger:             logger.NewNoopLogger(),
		UseTestDCs:         true,
		DomainFrontingHost: frontHost,
		DomainFrontingPort: uint(frontPort),
	}

	proxy, err := mtglib.NewProxy(*suite.opts)
	suite.NoError(err)

	suite.p = proxy

	listener, err := net.Listen("tcp", ":0")
	suite.NoError(err)

	suite.listener = listener

	go suite.p.Serve(suite.listener) //nolint: errcheck
}

func (suite *ProxyTestSuite) TearDownSuite() {
	if suite.listener != nil {
		suite.listener.Close() //nolint: errcheck
	}

	if suite.p != nil {
		suite.p.Shutdown()
	}

	if suite.frontServer != nil {
		suite.frontServer.Close()
	}
}

func (suite *ProxyTestSuite) TestCannotInitNoSecret() {
	opts := *suite.opts
	opts.Secret = mtglib.Secret{}

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoNetwork() {
	opts := *suite.opts
	opts.Network = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoAntiReplayCache() {
	opts := *suite.opts
	opts.AntiReplayCache = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoIPBlocklist() {
	opts := *suite.opts
	opts.IPBlocklist = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoIPAllowlist() {
	opts := *suite.opts
	opts.IPAllowlist = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoEventStream() {
	opts := *suite.opts
	opts.EventStream = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoLogger() {
	opts := *suite.opts
	opts.Logger = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitIncorrectPreferIP() {
	opts := *suite.opts
	opts.PreferIP = "xxx"

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestDomainFrontingAddress() {
	suite.Equal(suite.frontServer.Listener.Addr().String(), suite.p.DomainFrontingAddress())
}

func (suite *ProxyTestSuite) TestHTTPSRequest() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	addr := fmt.Sprintf("https://%s/headers", suite.ProxyAddress())

	resp, err := client.Get(addr) //nolint: noctx
	suite.Require().NoError(err)

	defer resp.Body.Close() //nolint: errcheck

	suite.Equal(http.StatusOK, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	suite.NoError(err)

	jsonStruct := struct {
		Headers struct {
			TraceID string `json:"X-Amzn-Trace-Id"` //nolint: tagliatelle
		} `json:"headers"`
	}{}

	suite.NoError(json.Unmarshal(data, &jsonStruct))
	suite.NotEmpty(jsonStruct.Headers.TraceID)
}

func TestProxy(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ProxyTestSuite{})
}
