package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// errRedirectBlocked marks a redirect hop refused by the egress guard. The dial
// wraps it, so the probe recognises it with errors.Is after RoundTrip.
var errRedirectBlocked = errors.New("redirect to a private address blocked")

// Address ranges that netip has no predicate for but that are just as internal
// as RFC 1918: carrier-grade NAT (RFC 6598) and "this network" (RFC 791).
var (
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork        = netip.MustParsePrefix("0.0.0.0/8")
)

// isPrivateAddr reports whether a is an address a redirect from a monitored
// target must not reach when block_private_redirects is set: loopback, private
// (RFC 1918 / RFC 4193), link-local (including the 169.254.169.254 cloud
// metadata endpoint), unspecified, carrier-grade NAT or "this network".
// IPv4-mapped IPv6 addresses are unmapped first, so ::ffff:127.0.0.1 is caught
// as loopback.
//
// Parameters:
//   - a: the resolved address the probe is about to connect to.
//
// It returns true when the address is internal.
func isPrivateAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() ||
		a.IsPrivate() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() ||
		a.IsUnspecified() ||
		sharedAddressSpace.Contains(a) ||
		thisNetwork.Contains(a)
}

// hostKey returns the canonical host of a URL for the "same host" decision of
// the egress guard: lowercased, port and trailing dot removed. Scheme and port
// are deliberately ignored, so http://intranet -> https://intranet:8443 stays
// the target's own host.
func hostKey(raw string) string {
	return strings.TrimSuffix(strings.ToLower(hostname(raw)), ".")
}

// egressGuardKey is the context key under which a hop carries its address
// predicate to the dialer.
type egressGuardKey struct{}

// withEgressGuard returns a context that makes guardedDialer refuse every
// address for which blocked returns true.
func withEgressGuard(ctx context.Context, blocked func(netip.Addr) bool) context.Context {
	return context.WithValue(ctx, egressGuardKey{}, blocked)
}

// guardedDialer wraps base so a dial whose context carries an egress guard
// checks the address it actually connects to.
//
// The check runs in the dialer's Control hook, i.e. on the resolved IP right
// before connect(2). Checking the hostname beforehand would be open to DNS
// rebinding: a name that resolves to a public address during the check and to
// 127.0.0.1 during the dial. Every address the dialer tries (IPv4 and IPv6,
// fallbacks) passes through the hook, so none of them slips past.
//
// Requests without a guard in their context dial exactly as base would; the
// guard is passed per request rather than stored on the transport because the
// transport is shared by all hops of a probe.
func guardedDialer(base *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		blocked, ok := ctx.Value(egressGuardKey{}).(func(netip.Addr) bool)
		if !ok || blocked == nil {
			return base.DialContext(ctx, network, address)
		}
		d := *base
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				// Fail closed: an address the guard cannot read is not one it
				// can vouch for.
				return fmt.Errorf("%w: unparsable address %q", errRedirectBlocked, address)
			}
			if blocked(ap.Addr()) {
				return fmt.Errorf("%w: %s", errRedirectBlocked, ap.Addr().Unmap())
			}
			return nil
		}
		return d.DialContext(ctx, network, address)
	}
}

// anyResolvesBlocked is the best-effort guard for a hop sent through an HTTP
// proxy: the dialer then only sees the proxy's address, so the hop's host is
// resolved here instead. It is weaker than the dial-time check — the proxy
// resolves the name again and may get a different answer — and is documented as
// such. A lookup failure does not block; the proxy reports its own error.
//
// Parameters:
//   - ctx: bounds the lookup by the probe's deadline.
//   - resolver: the resolver to use (net.DefaultResolver in production).
//   - host: the hop's host name or IP literal.
//   - blocked: the address predicate.
//
// It returns true when at least one resolved address is blocked.
func anyResolvesBlocked(ctx context.Context, resolver *net.Resolver, host string, blocked func(netip.Addr) bool) bool {
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if blocked(a) {
			return true
		}
	}
	return false
}
