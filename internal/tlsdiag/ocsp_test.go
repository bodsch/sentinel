package tlsdiag

import (
	"crypto/x509"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// inspectWithStaple runs Inspect over the chain with the given stapled response.
func inspectWithStaple(t *testing.T, c chain, staple []byte) *Info {
	t.Helper()
	state := stateFor(c.presented())
	state.OCSPResponse = staple
	info, _ := Inspect(state, testHost, refTime, c.roots, false)
	return info
}

func TestInspectStapleGood(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info := inspectWithStaple(t, c, stapleFor(t, c, ocsp.Good, refTime))

	if info.OCSP == nil {
		t.Fatal("stapled response not reported")
	}
	if info.OCSP.Status != StatusGood {
		t.Errorf("status = %q (%s), want good", info.OCSP.Status, info.OCSP.Error)
	}
	if !info.OCSP.Good() {
		t.Error("Good() should report true for a good staple")
	}
	if want := refTime.Add(24 * time.Hour); !info.OCSP.NextUpdate.Equal(want) {
		t.Errorf("next update = %v, want %v", info.OCSP.NextUpdate, want)
	}
	if info.OCSP.RevokedAt.IsZero() != true {
		t.Errorf("revoked at = %v, want zero for a good staple", info.OCSP.RevokedAt)
	}
}

func TestInspectStapleRevoked(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info := inspectWithStaple(t, c, stapleFor(t, c, ocsp.Revoked, refTime))

	if info.OCSP.Status != StatusRevoked {
		t.Fatalf("status = %q (%s), want revoked", info.OCSP.Status, info.OCSP.Error)
	}
	if info.OCSP.Good() {
		t.Error("Good() must be false for a revoked certificate")
	}
	if info.OCSP.RevokedAt.IsZero() {
		t.Error("revocation time not reported")
	}
}

func TestInspectStapleUnknown(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info := inspectWithStaple(t, c, stapleFor(t, c, ocsp.Unknown, refTime))

	if info.OCSP.Status != StatusUnknown {
		t.Errorf("status = %q, want unknown", info.OCSP.Status)
	}
	if info.OCSP.Good() {
		t.Error("Good() must be false for an unknown status")
	}
}

// TestInspectStapleUnparsable asserts a broken staple is reported as a finding
// rather than silently discarded.
func TestInspectStapleUnparsable(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info := inspectWithStaple(t, c, []byte("not a DER-encoded OCSP response"))

	if info.OCSP == nil {
		t.Fatal("a stapled but broken response must still be reported")
	}
	if info.OCSP.Status != StatusInvalid {
		t.Errorf("status = %q, want invalid", info.OCSP.Status)
	}
	if info.OCSP.Error == "" {
		t.Error("invalid staple should carry an explanation")
	}
}

// TestInspectStapleForDifferentCertificate covers a staple that is well-formed
// and correctly signed but refers to another certificate — it must not be
// accepted as evidence about this one.
func TestInspectStapleForDifferentCertificate(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	other := newChain(t, refTime, chainOptions{leafSerial: defaultSerial + 1})
	// Sign the response with c's issuer so only the serial number differs.
	mixed := chain{root: c.root, intermediate: c.intermediate, leaf: other.leaf, roots: c.roots}

	info := inspectWithStaple(t, c, stapleFor(t, mixed, ocsp.Good, refTime))

	if info.OCSP.Status != StatusInvalid {
		t.Errorf("status = %q, want invalid for a staple about another certificate", info.OCSP.Status)
	}
}

// TestInspectStapleSignedByStranger covers the MITM-flavoured case: a valid
// response signed by a CA that did not issue the certificate.
func TestInspectStapleSignedByStranger(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	stranger := newChain(t, refTime, chainOptions{})
	// c's leaf serial, but signed by an unrelated intermediate.
	forged := chain{root: stranger.root, intermediate: stranger.intermediate, leaf: c.leaf, roots: stranger.roots}

	info := inspectWithStaple(t, c, stapleFor(t, forged, ocsp.Good, refTime))

	if info.OCSP.Status != StatusInvalid {
		t.Errorf("status = %q, want invalid for a staple signed by a stranger", info.OCSP.Status)
	}
}

// TestInspectStapleWithoutIssuer covers a bare self-signed certificate: there is
// no issuer to verify the response against, so it cannot be trusted.
func TestInspectStapleWithoutIssuer(t *testing.T) {
	t.Parallel()

	leaf := selfSignedLeaf(t, refTime)
	state := stateFor([]*x509.Certificate{leaf})
	state.OCSPResponse = []byte{0x30, 0x03, 0x0a, 0x01, 0x00} // syntactically plausible

	info, _ := Inspect(state, testHost, refTime, x509.NewCertPool(), true)

	if info.OCSP == nil || info.OCSP.Status != StatusInvalid {
		t.Fatalf("OCSP = %+v, want invalid without an issuer", info.OCSP)
	}
	if info.OCSP.Error == "" {
		t.Error("missing explanation for the unverifiable staple")
	}
}

func TestInspectWithoutStaple(t *testing.T) {
	t.Parallel()

	c := newChain(t, refTime, chainOptions{})
	info := inspectWithStaple(t, c, nil)

	if info.OCSP != nil {
		t.Errorf("OCSP = %+v, want nil when nothing was stapled", info.OCSP)
	}
	if info.OCSP.Good() {
		t.Error("Good() must be false when no response was stapled")
	}
}
