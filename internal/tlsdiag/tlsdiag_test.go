package tlsdiag

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// refTime is the fixed reference time every test inspects against, so results
// never depend on when the suite runs.
var refTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// stateFor builds a handshake state carrying the given certificates, negotiated
// as TLS 1.3 unless a test overrides the fields afterwards.
func stateFor(certs []*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: certs,
	}
}

func TestInspectVerifiedChain(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info, reason := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if reason != probe.ReasonNone {
		t.Fatalf("reason = %q, want none", reason)
	}
	if !info.Valid || !info.HostnameValid || !info.ChainVerified {
		t.Errorf("valid=%v hostname=%v chainVerified=%v, want all true", info.Valid, info.HostnameValid, info.ChainVerified)
	}
	// The verified chain a client builds includes the root: leaf, intermediate,
	// root. The server only presented the first two.
	if info.ChainLength != 3 {
		t.Errorf("chain length = %d, want 3 (leaf + intermediate + root)", info.ChainLength)
	}
	if info.SelfSigned {
		t.Error("CA-issued leaf reported as self-signed")
	}
	if info.RemainingDays != 365 {
		t.Errorf("remaining days = %d, want 365", info.RemainingDays)
	}
}

// TestInspectChainEarliestExpiryUsesIntermediate covers the gap that motivated
// the chain metrics: an intermediate expiring before the leaf breaks the
// connection just as surely, but is invisible in leaf-only metrics.
func TestInspectChainEarliestExpiryUsesIntermediate(t *testing.T) {
	t.Parallel()

	intermediateExpiry := refTime.Add(10 * 24 * time.Hour)
	c := newChain(t, refTime, chainOptions{intermediateNotAfter: intermediateExpiry})

	info, reason := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)
	if reason != probe.ReasonNone {
		t.Fatalf("reason = %q, want none (the chain is still valid today)", reason)
	}

	if info.RemainingDays != 365 {
		t.Errorf("leaf remaining days = %d, want 365", info.RemainingDays)
	}
	if info.ChainEarliestRemainingDays != 10 {
		t.Errorf("chain earliest remaining days = %d, want 10", info.ChainEarliestRemainingDays)
	}
	if !info.ChainEarliestExpiry.Equal(intermediateExpiry) {
		t.Errorf("chain earliest expiry = %v, want %v", info.ChainEarliestExpiry, intermediateExpiry)
	}
}

// TestInspectFallsBackToPresentedChain asserts the diagnostics stay usable when
// verification fails — precisely when an operator needs them.
func TestInspectFallsBackToPresentedChain(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	// An empty pool trusts nothing, so no chain verifies.
	info, reason := Inspect(stateFor(c.presented()), testHost, refTime, x509.NewCertPool(), false)

	if reason != probe.ReasonCertificateInvalid {
		t.Fatalf("reason = %q, want certificate_invalid", reason)
	}
	if info.ChainVerified {
		t.Error("chain reported as verified against an empty root pool")
	}
	if info.ChainLength != 2 {
		t.Errorf("chain length = %d, want 2 (the presented leaf + intermediate)", info.ChainLength)
	}
	if info.ChainEarliestExpiry.IsZero() {
		t.Error("chain expiry missing on the fallback path")
	}
	// Identity must still be reported: it is how an operator recognises a
	// certificate they do not trust.
	if info.FingerprintSHA256 == "" || info.IssuerCN == "" {
		t.Errorf("leaf metadata missing on the fallback path: %+v", info)
	}
}

func TestInspectSkipVerifyReportsHonestly(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info, reason := Inspect(stateFor(c.presented()), testHost, refTime, x509.NewCertPool(), true)

	if reason != probe.ReasonNone {
		t.Fatalf("reason = %q, want none under skipVerify", reason)
	}
	if info.Valid || info.ChainVerified {
		t.Errorf("skipVerify must not fake trust: valid=%v chainVerified=%v", info.Valid, info.ChainVerified)
	}
	if !info.HostnameValid {
		t.Error("hostname should still verify")
	}
}

func TestInspectSelfSigned(t *testing.T) {
	t.Parallel()

	leaf := selfSignedLeaf(t, refTime)
	info, _ := Inspect(stateFor([]*x509.Certificate{leaf}), testHost, refTime, x509.NewCertPool(), true)

	if !info.SelfSigned {
		t.Error("self-signed certificate not detected")
	}
	if info.ChainLength != 1 {
		t.Errorf("chain length = %d, want 1", info.ChainLength)
	}
}

func TestInspectLeafMetadata(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{
		leafDNSNames: []string{testHost, "www." + testHost},
		leafIPs:      []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	info, _ := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if info.SubjectCN != testHost {
		t.Errorf("subject CN = %q, want %q", info.SubjectCN, testHost)
	}
	if info.IssuerCN != "Sentinel Test Intermediate CA" {
		t.Errorf("issuer CN = %q, want the intermediate", info.IssuerCN)
	}
	if len(info.FingerprintSHA256) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex characters", info.FingerprintSHA256)
	}
	if info.Serial != "1267" { // 4711 decimal
		t.Errorf("serial = %q, want hexadecimal 1267", info.Serial)
	}
	if len(info.SANs) == 0 {
		t.Error("SANs not recorded")
	}
	if info.PublicKeyAlgorithm != "ECDSA" {
		t.Errorf("public key algorithm = %q, want ECDSA", info.PublicKeyAlgorithm)
	}
	if info.KeyBits != 256 {
		t.Errorf("key bits = %d, want 256 for P-256", info.KeyBits)
	}
	if !strings.Contains(info.SignatureAlgorithm, "ECDSA") {
		t.Errorf("signature algorithm = %q, want an ECDSA variant", info.SignatureAlgorithm)
	}
	if info.SANCount != 3 {
		t.Errorf("SAN count = %d, want 3 (2 DNS + 1 IP)", info.SANCount)
	}
	if got := strings.Join(info.SANs, ","); got != testHost+",www."+testHost+",127.0.0.1" {
		t.Errorf("SANs = %q, want DNS names before IPs", got)
	}
	if !info.NotBefore.Equal(refTime.Add(-time.Hour)) {
		t.Errorf("not before = %v, want one hour before the reference time", info.NotBefore)
	}
}

func TestInspectRSAKeyBits(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{leafRSABits: 2048})
	info, _ := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if info.PublicKeyAlgorithm != "RSA" {
		t.Errorf("public key algorithm = %q, want RSA", info.PublicKeyAlgorithm)
	}
	if info.KeyBits != 2048 {
		t.Errorf("key bits = %d, want 2048", info.KeyBits)
	}
}

// TestInspectCapsRecordedSANs guards the memory bound: a probed server must not
// be able to make Sentinel retain an unbounded list, while the reported count
// stays accurate.
func TestInspectCapsRecordedSANs(t *testing.T) {
	t.Parallel()

	names := make([]string, 0, maxRecordedSANs+10)
	names = append(names, testHost)
	for i := range maxRecordedSANs + 9 {
		names = append(names, fmt.Sprintf("host-%d.%s", i, testHost))
	}

	c := newChain(t, refTime, chainOptions{leafDNSNames: names})
	info, _ := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if len(info.SANs) != maxRecordedSANs {
		t.Errorf("recorded SANs = %d, want the cap of %d", len(info.SANs), maxRecordedSANs)
	}
	if info.SANCount != len(names) {
		t.Errorf("SAN count = %d, want the untruncated %d", info.SANCount, len(names))
	}
}

func TestInspectNegotiatedConnection(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	state := stateFor(c.presented())
	state.Version = tls.VersionTLS12
	state.CipherSuite = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

	info, _ := Inspect(state, testHost, refTime, c.roots, false)

	if info.Version != tls.VersionTLS12 || info.VersionName != "TLS 1.2" {
		t.Errorf("version = %#x / %q, want TLS 1.2", info.Version, info.VersionName)
	}
	if info.CipherName != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("cipher = %q, unexpected", info.CipherName)
	}
}

// TestInspectValidityFailures pins the classification of the security-critical
// certificate problems, which stay unchanged from before the diagnostics were
// extended.
func TestInspectValidityFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts chainOptions
		host string
		now  time.Time
		want probe.FailureReason
	}{
		{
			name: "expired",
			opts: chainOptions{leafNotAfter: refTime.Add(-24 * time.Hour)},
			host: testHost,
			now:  refTime,
			want: probe.ReasonCertificateExpired,
		},
		{
			name: "not yet valid",
			opts: chainOptions{},
			host: testHost,
			now:  refTime.Add(-48 * time.Hour),
			want: probe.ReasonCertificateInvalid,
		},
		{
			name: "hostname mismatch",
			opts: chainOptions{leafDNSNames: []string{"other.test"}},
			host: testHost,
			now:  refTime,
			want: probe.ReasonCertificateInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newChain(t, refTime, tc.opts)
			info, reason := Inspect(stateFor(c.presented()), tc.host, tc.now, c.roots, false)
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
			if info == nil {
				t.Fatal("diagnostics must be reported even for a rejected certificate")
			}
			if info.Valid {
				t.Error("a rejected certificate must not report Valid")
			}
		})
	}
}

// TestInspectExpiredYieldsNegativeDays covers the flooring rule: a certificate
// that expired hours ago must still report a negative day count.
func TestInspectExpiredYieldsNegativeDays(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{leafNotAfter: refTime.Add(-2 * time.Hour)})
	info, _ := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if info.RemainingDays >= 0 {
		t.Errorf("remaining days = %d, want negative", info.RemainingDays)
	}
	if info.ChainEarliestRemainingDays >= 0 {
		t.Errorf("chain remaining days = %d, want negative", info.ChainEarliestRemainingDays)
	}
}

func TestInspectWithoutCertificates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state *tls.ConnectionState
	}{
		{"nil state", nil},
		{"no peer certificates", &tls.ConnectionState{Version: tls.VersionTLS13}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info, reason := Inspect(tc.state, testHost, refTime, nil, false)
			if reason != probe.ReasonTLSError {
				t.Errorf("reason = %q, want tls_error", reason)
			}
			if info != nil {
				t.Errorf("info = %+v, want nil", info)
			}
		})
	}
}

// TestInspectSerialKeepsLeadingZero pins the byte-wise rendering: a serial whose
// first byte is below 0x10 must keep its leading zero, or it cannot be pasted
// into a certificate transparency search.
func TestInspectSerialKeepsLeadingZero(t *testing.T) {
	t.Parallel()

	// 0x0912 — an integer-formatted serial would render this as "912".
	c := newChain(t, refTime, chainOptions{leafSerial: 0x0912})
	info, _ := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)

	if info.Serial != "0912" {
		t.Errorf("serial = %q, want 0912 with its leading zero", info.Serial)
	}
}

// TestInspectChainExpirySpansPresentedAndVerified covers the two ways a chain
// can expire that a single certificate set would miss.
func TestInspectChainExpirySpansPresentedAndVerified(t *testing.T) {
	t.Parallel()

	t.Run("superfluous presented certificate", func(t *testing.T) {
		t.Parallel()

		// A cross-signed intermediate the server sends but Go routes around. It
		// is absent from the verified chain, yet a client whose trust store
		// needs it would fail once it lapses — so it must count.
		soon := refTime.Add(3 * 24 * time.Hour)
		c := newChain(t, refTime, chainOptions{})
		stranger := newChain(t, refTime, chainOptions{intermediateNotAfter: soon})

		presented := append(c.presented(), stranger.intermediate.cert)
		info, reason := Inspect(stateFor(presented), testHost, refTime, c.roots, false)

		if reason != probe.ReasonNone {
			t.Fatalf("reason = %q, want none", reason)
		}
		if info.ChainLength != 3 {
			t.Errorf("chain length = %d, want the 3-certificate verified chain", info.ChainLength)
		}
		if info.ChainEarliestRemainingDays != 3 {
			t.Errorf("chain earliest remaining days = %d, want 3 from the superfluous certificate", info.ChainEarliestRemainingDays)
		}
	})

	t.Run("root expiring first", func(t *testing.T) {
		t.Parallel()

		// The root appears only in the verified chain, never on the wire — and
		// when it lapses, every client fails.
		soon := refTime.Add(5 * 24 * time.Hour)
		c := newChain(t, refTime, chainOptions{rootNotAfter: soon})

		info, reason := Inspect(stateFor(c.presented()), testHost, refTime, c.roots, false)
		if reason != probe.ReasonNone {
			t.Fatalf("reason = %q, want none", reason)
		}
		if info.ChainEarliestRemainingDays != 5 {
			t.Errorf("chain earliest remaining days = %d, want 5 from the root", info.ChainEarliestRemainingDays)
		}
	})
}
