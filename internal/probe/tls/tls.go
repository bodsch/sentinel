// Package tls implements the standalone TLS probe: it connects to any endpoint
// that speaks TLS immediately on connect — LDAPS, SMTPS, IMAPS, MQTT over TLS,
// or a bare TLS port — completes the handshake, and inspects the certificate.
//
// It exists because such endpoints carry no HTTP to probe them with, while the
// TCP probe sees only that a connection can be opened and never the certificate
// behind it. No application protocol is spoken after the handshake: the probe
// connects, inspects, and closes.
//
// STARTTLS (ports 587, 143, 389 …) is deliberately out of scope. Upgrading a
// plaintext connection needs a protocol-specific dialogue, which belongs with
// the mail and directory protocols themselves rather than in a generic TLS
// check.
//
// The certificate inspection, the failure classification and the exported
// sentinel_tls_* series are all shared with the HTTPS path; this package
// contributes the dialling, the handshake and three phase-timing metrics.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/tlsdiag"
)

// ProbeType is the protocol identifier for TLS probes.
const ProbeType = "tls"

// Options carries the fully-resolved settings for one TLS target. The caller
// (the scheduler) builds it from the validated configuration, keeping this
// package independent of the config package.
type Options struct {
	// Name is the target name (for reference/logging).
	Name string
	// Host is the hostname or IP address to connect to.
	Host string
	// Port is the TCP port.
	Port int
	// Timeout is the total per-run timeout covering resolution, connect and
	// handshake.
	Timeout time.Duration

	// ServerName overrides the SNI name and the name the certificate is
	// validated against. Empty means: use Host, and send no SNI when Host is an
	// IP literal (crypto/tls omits SNI for IP addresses).
	ServerName string
	// ALPN are the application protocols offered, most preferred first. Empty
	// offers none.
	ALPN []string
	// SkipVerify accepts any certificate; validity is still reported honestly.
	SkipVerify bool
	// Roots is the trust anchor pool; nil means the system roots.
	Roots *x509.CertPool
	// ClientCert is the client identity presented on request (mutual TLS).
	ClientCert *tls.Certificate
	// MaxVersion caps the highest offered TLS version; zero means Go's default.
	MaxVersion uint16
	// Policy holds the target's opt-in TLS expectations. Nil or empty enforces
	// nothing.
	Policy *tlsdiag.Policy
}

// Prober runs TLS checks for a single target. It satisfies probe.Prober.
type Prober struct {
	name       string
	host       string
	port       string
	timeout    time.Duration
	serverName string
	alpn       []string
	skipVerify bool
	roots      *x509.CertPool
	clientCert *tls.Certificate
	maxVersion uint16
	policy     *tlsdiag.Policy
	resolver   resolver

	// Per-run handshake state, written by verifyConnection during the
	// (synchronous, same-goroutine) handshake and read once it returns. A Prober
	// only ever runs one probe at a time (the scheduler's skip-if-running), so
	// these need no synchronisation.
	info   *tlsdiag.Info
	reason probe.FailureReason
	// certRequested records whether the server asked for a client certificate
	// during this run.
	certRequested bool
}

// compile-time checks.
var (
	_ probe.Prober = (*Prober)(nil)
	_ interface {
		probe.Diagnostics
		tlsdiag.Provider
	} = (*Diagnostics)(nil)
)

// New builds a Prober from resolved options.
//
// Parameters:
//   - opts: the resolved target settings.
//
// It returns an error for an invalid timeout, an empty host or a port outside
// 1-65535. Configuration validation rejects those already, so these are
// defensive.
func New(opts Options) (*Prober, error) {
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("tls probe %q: timeout must be greater than zero", opts.Name)
	}
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		return nil, fmt.Errorf("tls probe %q: host is required", opts.Name)
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return nil, fmt.Errorf("tls probe %q: port %d is out of range 1-65535", opts.Name, opts.Port)
	}

	return &Prober{
		name:       opts.Name,
		host:       host,
		port:       strconv.Itoa(opts.Port),
		timeout:    opts.Timeout,
		serverName: strings.TrimSpace(opts.ServerName),
		alpn:       opts.ALPN,
		skipVerify: opts.SkipVerify,
		roots:      opts.Roots,
		clientCert: opts.ClientCert,
		maxVersion: opts.MaxVersion,
		policy:     opts.Policy,
		resolver:   net.DefaultResolver,
	}, nil
}

// Type implements probe.Prober.
func (p *Prober) Type() string { return ProbeType }

// Probe implements probe.Prober. It applies the target's total timeout, connects
// and completes the handshake, and returns a typed Result. It never returns an
// error: a failed check is a successful execution with Success=false.
func (p *Prober) Probe(ctx context.Context) probe.Result {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	start := time.Now()
	diag, timings, reason := p.run(ctx)
	end := time.Now()

	return probe.Result{
		Success:       reason == probe.ReasonNone,
		FailureReason: reason,
		Duration:      end.Sub(start),
		Timings:       timings,
		Diagnostics:   diag,
		Timestamp:     end,
	}
}

// run resolves, connects, handshakes and inspects, returning the diagnostics
// gathered so far, the phase timings, and the failure reason (ReasonNone on
// success).
func (p *Prober) run(ctx context.Context) (*Diagnostics, probe.Timings, probe.FailureReason) {
	var timings probe.Timings
	diag := &Diagnostics{ServerName: p.sni()}

	p.info = nil
	p.reason = probe.ReasonNone
	p.certRequested = false

	conn, err := dialTCP(ctx, p.resolver, p.host, p.port)
	if conn != nil {
		timings.DNS = conn.dns
		timings.Connect = conn.connect
	}
	if err != nil {
		return diag, timings, probe.ClassifyNetworkError(err)
	}
	defer func() { _ = conn.conn.Close() }()
	diag.Endpoint = conn.endpoint

	tlsConn := tls.Client(conn.conn, p.clientConfig())

	handshakeStart := time.Now()
	err = tlsConn.HandshakeContext(ctx)
	timings.TLS = time.Since(handshakeStart)

	// verifyConnection records the diagnostics even when it then aborts the
	// handshake, so a rejected certificate is still fully described.
	if p.info != nil {
		diag.TLS = p.info
		diag.ALPN = p.info.ALPN
	}
	if err != nil {
		if p.reason != probe.ReasonNone {
			return diag, timings, p.reason
		}
		return diag, timings, probe.ClassifyNetworkError(err)
	}

	if reason := p.confirmAccepted(ctx, tlsConn); reason != probe.ReasonNone {
		return diag, timings, reason
	}

	return diag, timings, p.policy.Evaluate(diag.TLS)
}

// acceptanceWindow bounds how long confirmAccepted waits for the server to
// object. One round trip is enough for the alert to arrive; the window is
// generous but still short enough not to distort a probe noticeably.
const acceptanceWindow = 250 * time.Millisecond

// confirmAccepted checks that the server did not reject our client certificate.
//
// Under TLS 1.3 the client considers the handshake complete as soon as it has
// sent its own Finished message — before the server has validated the client
// certificate. A server that rejects the identity replies with an alert that
// only surfaces on the next read, so without this check a target requiring mutual
// TLS would report success while being entirely unusable.
//
// It only runs when the server asked for a client certificate — the sole case in
// which it can reject *us*, whether because the identity we presented was
// unacceptable or because we had none to present. Skipping it otherwise keeps
// the overwhelmingly common probe free of a needless wait.
//
// Parameters:
//   - ctx: the probe context, so a cancelled probe returns promptly.
//   - conn: the freshly handshaken connection.
//
// It returns ReasonNone when the connection is usable. A read timeout means the
// server is simply waiting for application data, and end-of-file means it closed
// cleanly — both are healthy for an endpoint that speaks first only after a
// request.
func (p *Prober) confirmAccepted(ctx context.Context, conn *tls.Conn) probe.FailureReason {
	if !p.certRequested {
		return probe.ReasonNone
	}

	deadline := time.Now().Add(acceptanceWindow)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return probe.ReasonNone
	}

	var buf [1]byte
	_, err := conn.Read(buf[:])
	switch {
	case err == nil:
		// Unexpected application data, but the connection plainly works.
		return probe.ReasonNone
	case errors.Is(err, io.EOF):
		return probe.ReasonNone
	case errors.Is(err, os.ErrDeadlineExceeded):
		return probe.ReasonNone
	default:
		return probe.ClassifyNetworkError(err)
	}
}

// verifyConnection runs during the TLS handshake and decides whether it may
// complete. It records the certificate diagnostics and returns an error —
// aborting the handshake — when the certificate is unacceptable.
//
// Verifying here rather than after the handshake matters for mutual TLS: the
// client certificate is sent only after the server's certificate has been
// processed, so aborting now keeps Sentinel's own identity from reaching a peer
// it does not trust. Without a client certificate nothing is disclosed either
// way, but doing it uniformly keeps one code path and mirrors the HTTP probe.
func (p *Prober) verifyConnection(cs tls.ConnectionState) error {
	info, reason := tlsdiag.Inspect(&cs, p.verificationHost(), time.Now(), p.roots, p.skipVerify)
	p.info = info
	p.reason = reason
	if reason != probe.ReasonNone {
		return fmt.Errorf("tls: %s", reason)
	}
	return nil
}

// clientConfig builds the TLS configuration for one handshake.
//
// Like the HTTP probe it dials with InsecureSkipVerify and verifies in
// VerifyConnection instead, so a rejected certificate still yields full
// diagnostics (expiry, issuer, chain) rather than an opaque handshake error.
// This is not "TLS off": the certificate is inspected and, by default, rejected
// when untrusted.
func (p *Prober) clientConfig() *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection during the handshake.
		VerifyConnection:   p.verifyConnection,
		ServerName:         p.sni(),
		NextProtos:         p.alpn,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         p.maxVersion,
	}
	// Always installed, even without a configured identity: the callback is how
	// the probe learns that the server asked for a client certificate at all,
	// which is what confirmAccepted keys off.
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		p.certRequested = true
		if p.clientCert == nil {
			// The empty certificate is how crypto/tls is told "I have none",
			// leaving it to the server whether to proceed.
			return &tls.Certificate{}, nil
		}
		return p.clientCert, nil
	}
	return cfg
}

// sni returns the name to send in the SNI extension: the configured override,
// otherwise the host — except for an IP literal, for which crypto/tls sends no
// SNI at all.
func (p *Prober) sni() string {
	if p.serverName != "" {
		return p.serverName
	}
	if net.ParseIP(p.host) != nil {
		return ""
	}
	return p.host
}

// verificationHost returns the name the certificate must be valid for: the
// server_name override when set, otherwise the connect host.
func (p *Prober) verificationHost() string {
	if p.serverName != "" {
		return p.serverName
	}
	return p.host
}
