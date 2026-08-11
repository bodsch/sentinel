package tls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// resolver abstracts name resolution so tests can inject a deterministic one.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// connection is an established TCP connection plus the phase timings measured
// while establishing it.
type connection struct {
	conn net.Conn
	// endpoint is the "ip:port" actually connected to, which tells an operator
	// which backend answered when a name has several addresses.
	endpoint string
	dns      time.Duration
	connect  time.Duration
}

// dialTCP resolves the host and opens a TCP connection, timing the two phases
// separately.
//
// Name resolution is performed explicitly rather than left to net.Dialer,
// because the split is the point: "slow to resolve" and "slow to connect" call
// for entirely different investigations, and Sentinel's reason for existing is
// to tell them apart. The cost is that this does not implement Happy Eyeballs —
// addresses are tried in order rather than racing IPv4 against IPv6 — which for
// a monitoring probe is the better trade: the measurement stays attributable to
// one address, and trying every address in turn is still tolerant of a broken
// IPv6 path.
//
// Parameters:
//   - ctx: carries the probe deadline; both phases observe it.
//   - res: the resolver to use.
//   - host: hostname or IP literal.
//   - port: the TCP port as a string.
//
// It returns the established connection with its timings, or an error from the
// last address attempted.
func dialTCP(ctx context.Context, res resolver, host, port string) (*connection, error) {
	out := &connection{}

	dnsStart := time.Now()
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	out.dns = time.Since(dnsStart)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses returned", Name: host, IsNotFound: true}
	}

	var dialer net.Dialer
	connectStart := time.Now()
	var lastErr error
	for _, addr := range addrs {
		// Stop early on a cancelled or expired context rather than working
		// through every remaining address after the budget is gone.
		if ctx.Err() != nil {
			out.connect = time.Since(connectStart)
			return nil, ctx.Err()
		}

		endpoint := net.JoinHostPort(addr.Unmap().String(), port)
		conn, derr := dialer.DialContext(ctx, "tcp", endpoint)
		if derr != nil {
			lastErr = derr
			continue
		}
		out.connect = time.Since(connectStart)
		out.conn = conn
		out.endpoint = endpoint
		return out, nil
	}

	out.connect = time.Since(connectStart)
	if lastErr == nil {
		lastErr = errors.New("no address could be dialled")
	}
	return nil, fmt.Errorf("connecting to %s: %w", net.JoinHostPort(host, port), lastErr)
}
