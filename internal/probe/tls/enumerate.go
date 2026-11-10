package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// enumWorkers bounds the handshakes run at once during an enumeration. A few in
// parallel keep a slow server from stretching the run, without looking like a
// burst to the server's connection limits.
const enumWorkers = 4

// DefaultEnumerateInterval is how often an enumeration runs when the target sets
// none: the supported versions and suites change with a deployment, not
// between two probes.
const DefaultEnumerateInterval = time.Hour

// enumVersions are the protocol versions an enumeration tries, oldest first.
// SSLv3 is absent because crypto/tls cannot speak it.
var enumVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

// versionNames maps the configuration spelling of a version to its code.
var versionNames = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

// ParseEnumVersion maps "1.0" … "1.3" to the TLS version code.
//
// Parameters:
//   - s: the version as written in the configuration.
//
// It returns the code and true, or false for an unknown spelling.
func ParseEnumVersion(s string) (uint16, bool) {
	v, ok := versionNames[s]
	return v, ok
}

// EnumerateOptions configures the periodic version and cipher-suite
// enumeration of a target.
type EnumerateOptions struct {
	// Interval is the minimum time between two enumerations; zero means
	// DefaultEnumerateInterval.
	Interval time.Duration
	// ForbidVersions are versions the server must not accept.
	ForbidVersions []uint16
	// ForbidInsecureCiphers fails the target when the server accepts any suite
	// crypto/tls classifies as insecure (RC4, 3DES, RSA key exchange, CBC with
	// SHA-256).
	ForbidInsecureCiphers bool
}

// Enumeration is the result of one enumeration run.
type Enumeration struct {
	// At is when the run finished.
	At time.Time
	// Complete is false when at least one handshake gave no definite answer
	// (timeout, connection failure); the affected entries have Known=false.
	Complete bool
	// Versions holds one entry per version in enumVersions.
	Versions []VersionSupport
	// Ciphers holds one entry per TLS 1.0–1.2 suite crypto/tls can offer,
	// tried at CipherVersion.
	Ciphers []CipherSupport
	// CipherVersion is the version the suites were tried at: the highest
	// supported version up to TLS 1.2. Zero when the server supports none of
	// them, in which case every suite is known to be unsupported.
	CipherVersion uint16
}

// VersionSupport says whether the server accepted one protocol version.
type VersionSupport struct {
	Version   uint16
	Supported bool
	// Known is false when the handshake gave no definite answer.
	Known bool
}

// CipherSupport says whether the server accepted one cipher suite.
type CipherSupport struct {
	ID        uint16
	Name      string
	Insecure  bool
	Supported bool
	Known     bool
}

// InsecureSupported returns the accepted suites classified as insecure.
func (e *Enumeration) InsecureSupported() []CipherSupport {
	var out []CipherSupport
	for _, c := range e.Ciphers {
		if c.Known && c.Supported && c.Insecure {
			out = append(out, c)
		}
	}
	return out
}

// violates reports whether the enumeration breaches the target's rules. Only
// definite answers count: an unknown entry is no evidence either way.
func (o *EnumerateOptions) violates(e *Enumeration) bool {
	if o == nil || e == nil {
		return false
	}
	for _, v := range e.Versions {
		if v.Known && v.Supported && slices.Contains(o.ForbidVersions, v.Version) {
			return true
		}
	}
	return o.ForbidInsecureCiphers && len(e.InsecureSupported()) > 0
}

// enumerableSuites lists every suite crypto/tls can offer below TLS 1.3. TLS
// 1.3 suites are not configurable in crypto/tls and are therefore not
// enumerated.
func enumerableSuites() []*tls.CipherSuite {
	var out []*tls.CipherSuite
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if slices.ContainsFunc(s.SupportedVersions, func(v uint16) bool { return v <= tls.VersionTLS12 }) {
			out = append(out, s)
		}
	}
	return out
}

// enumerationDue reports whether a new enumeration should run now.
func (p *Prober) enumerationDue(now time.Time) bool {
	if p.enumerate == nil {
		return false
	}
	interval := p.enumerate.Interval
	if interval <= 0 {
		interval = DefaultEnumerateInterval
	}
	return p.lastEnum == nil || now.Sub(p.lastEnum.At) >= interval
}

// runEnumeration tries every version and suite against endpoint.
//
// Parameters:
//   - ctx: the scheduler's context; cancelling it (shutdown) stops the run.
//     Each handshake gets the target's timeout on top.
//   - endpoint: the "ip:port" the main probe connected to, so every handshake
//     reaches the same backend.
//
// It returns the enumeration; it does not fail as a whole.
func (p *Prober) runEnumeration(ctx context.Context, endpoint string) *Enumeration {
	e := &Enumeration{Complete: true}

	e.Versions = make([]VersionSupport, len(enumVersions))
	p.parallel(ctx, len(enumVersions), func(i int) {
		ok, known := p.tryHandshake(ctx, endpoint, enumVersions[i], 0)
		e.Versions[i] = VersionSupport{Version: enumVersions[i], Supported: ok, Known: known}
	})

	for _, v := range e.Versions {
		if v.Known && v.Supported && v.Version <= tls.VersionTLS12 {
			e.CipherVersion = v.Version // ascending order: the last hit is the highest
		}
	}

	suites := enumerableSuites()
	e.Ciphers = make([]CipherSupport, len(suites))
	for i, s := range suites {
		e.Ciphers[i] = CipherSupport{ID: s.ID, Name: s.Name, Insecure: s.Insecure}
	}
	switch {
	case e.CipherVersion != 0:
		p.parallel(ctx, len(suites), func(i int) {
			if !slices.Contains(suites[i].SupportedVersions, e.CipherVersion) {
				// The suite cannot exist at this version (e.g. GCM below 1.2).
				e.Ciphers[i].Known = true
				return
			}
			ok, known := p.tryHandshake(ctx, endpoint, e.CipherVersion, suites[i].ID)
			e.Ciphers[i].Supported, e.Ciphers[i].Known = ok, known
		})
	case allKnown(e.Versions):
		// No version up to 1.2 is supported, so no such suite can be.
		for i := range e.Ciphers {
			e.Ciphers[i].Known = true
		}
	}

	for _, v := range e.Versions {
		e.Complete = e.Complete && v.Known
	}
	for _, c := range e.Ciphers {
		e.Complete = e.Complete && c.Known
	}
	e.At = time.Now()
	return e
}

// parallel runs fn for 0..n-1 on at most enumWorkers goroutines.
func (p *Prober) parallel(ctx context.Context, n int, fn func(i int)) {
	sem := make(chan struct{}, enumWorkers)
	var wg sync.WaitGroup
	for i := range n {
		if ctx.Err() != nil {
			break // entries left zero stay Known=false
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(i)
		})
	}
	wg.Wait()
}

// tryHandshake attempts one handshake restricted to a single version and,
// below TLS 1.3, a single suite.
//
// Parameters:
//   - ctx: the enumeration context.
//   - endpoint: the "ip:port" to dial.
//   - version: the only version offered.
//   - suite: the only suite offered; zero offers every enumerable suite of
//     the version, so a version test does not depend on which suites the
//     server happens to share with crypto/tls's defaults — a server that
//     speaks only 3DES still supports TLS 1.2.
//
// It returns whether the server accepted, and whether the answer is definite:
// a refusal by the server (alert, closed connection, a different version or
// suite chosen) is a definite "no", while a timeout or a failed dial is not.
func (p *Prober) tryHandshake(ctx context.Context, endpoint string, version, suite uint16) (supported, known bool) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return false, false
	}
	defer func() { _ = conn.Close() }()

	if p.startTLS != StartTLSNone {
		if err := upgrade(ctx, conn, p.startTLS); err != nil {
			// The upgrade worked in the main probe; failing here says nothing
			// about the version or suite.
			return false, false
		}
	}

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // only acceptance is measured; the certificate is checked by the main probe.
		ServerName:         p.sni(),
		MinVersion:         version,
		MaxVersion:         version,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if p.clientCert == nil {
				return &tls.Certificate{}, nil
			}
			return p.clientCert, nil
		},
	}
	switch {
	case suite != 0:
		cfg.CipherSuites = []uint16{suite}
	case version <= tls.VersionTLS12:
		for _, s := range enumerableSuites() {
			if slices.Contains(s.SupportedVersions, version) {
				cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
			}
		}
	}

	tc := tls.Client(conn, cfg)
	err = tc.HandshakeContext(ctx)
	switch {
	case err == nil:
		st := tc.ConnectionState()
		return st.Version == version && (suite == 0 || st.CipherSuite == suite), true
	case ctx.Err() != nil:
		return false, false
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false, false
		}
		return false, true
	}
}

// allKnown reports whether every version entry has a definite answer.
func allKnown(vs []VersionSupport) bool {
	for _, v := range vs {
		if !v.Known {
			return false
		}
	}
	return true
}

// enumerationReason evaluates the cached enumeration against the target's
// rules.
func (p *Prober) enumerationReason() probe.FailureReason {
	if p.enumerate.violates(p.lastEnum) {
		return probe.ReasonTLSPolicyViolation
	}
	return probe.ReasonNone
}
