package cli

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/mhsanaei/mtg-multi/mtglib"
)

type sniCheckResult struct {
	ResolvedIP4 []string
	ResolvedIP6 []string
	OurIP4      string
	OurIP6      string
}

// runSNICheck resolves host and compares the records with this server's
// public IPv4 and IPv6. host is passed explicitly rather than read from
// conf.Secret.Host so multi-secret configs can check the first secret's host
// (see Doctor.getFirstSecretHost).
func runSNICheck(
	ctx context.Context,
	conf *config.Config,
	resolver *net.Resolver,
	ntw mtglib.Network,
	host string,
) (sniCheckResult, error) {
	res := sniCheckResult{}

	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return res, fmt.Errorf("cannot resolve addresses of %s: %w", host, err)
	}

	if len(addrs) == 0 {
		return res, fmt.Errorf("no known addresses for %s", host)
	}

	for _, addr := range addrs {
		if ip := addr.IP.To4(); ip == nil {
			res.ResolvedIP6 = append(res.ResolvedIP6, addr.IP.To16().String())
		} else {
			res.ResolvedIP4 = append(res.ResolvedIP4, ip.String())
		}
	}

	wg := &sync.WaitGroup{}

	if len(res.ResolvedIP4) > 0 {
		wg.Go(func() {
			ip := conf.PublicIPv4.Get(nil)
			if ip == nil {
				ip, _ = getIP(ctx, ntw, "tcp4")
			}

			if ip != nil {
				res.OurIP4 = ip.To4().String()
			}
		})
	}

	if len(res.ResolvedIP6) > 0 {
		wg.Go(func() {
			ip := conf.PublicIPv6.Get(nil)
			if ip == nil {
				ip, _ = getIP(ctx, ntw, "tcp6")
			}

			if ip != nil {
				res.OurIP6 = ip.To16().String()
			}
		})
	}

	wg.Wait()

	return res, nil
}
