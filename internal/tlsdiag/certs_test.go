package tlsdiag

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// testHost is the hostname every generated leaf certificate is valid for.
const testHost = "sentinel.test"

// issuedCert is a generated certificate together with the key that signs its
// children, so a test can keep building a chain from it.
type issuedCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// chain is a complete root -> intermediate -> leaf test hierarchy plus the trust
// pool needed to verify it. Building a real multi-level chain (rather than the
// single self-signed certificate the HTTP probe tests use) is what makes the
// chain metrics testable at all: the interesting case — an intermediate that
// expires before the leaf — cannot exist without one.
type chain struct {
	root         issuedCert
	intermediate issuedCert
	leaf         issuedCert
	roots        *x509.CertPool
}

// presented returns the certificates in the order a TLS server sends them: leaf
// first, then the intermediates, without the root.
func (c chain) presented() []*x509.Certificate {
	return []*x509.Certificate{c.leaf.cert, c.intermediate.cert}
}

// chainOptions tunes the generated hierarchy. The zero value produces a chain in
// which every certificate is valid for a year.
type chainOptions struct {
	// rootNotAfter overrides the root's expiry; zero means one year and a day
	// from now.
	rootNotAfter time.Time
	// intermediateNotAfter overrides the intermediate's expiry; zero means one
	// year from now.
	intermediateNotAfter time.Time
	// leafNotAfter overrides the leaf's expiry; zero means one year from now.
	leafNotAfter time.Time
	// leafDNSNames overrides the leaf's DNS SANs; nil means [testHost].
	leafDNSNames []string
	// leafIPs adds IP SANs to the leaf.
	leafIPs []net.IP
	// leafRSABits, when non-zero, gives the leaf an RSA key of that size
	// instead of the default P-256 ECDSA key.
	leafRSABits int
	// leafSerial overrides the leaf's serial number; zero means defaultSerial.
	leafSerial int64
}

// defaultSerial is the leaf serial number tests see unless they override it.
const defaultSerial = 4711

// newChain builds a root CA, an intermediate CA signed by it, and a leaf signed
// by the intermediate.
//
// Parameters:
//   - t: the test, used for fatal errors on generation failure.
//   - now: the reference time; every certificate becomes valid one hour earlier.
//   - opts: optional overrides for validity windows, SANs and key type.
//
// It returns the assembled chain including a root pool that trusts it.
func newChain(t testing.TB, now time.Time, opts chainOptions) chain {
	t.Helper()

	year := now.Add(365 * 24 * time.Hour)
	notBefore := now.Add(-time.Hour)

	if opts.intermediateNotAfter.IsZero() {
		opts.intermediateNotAfter = year
	}
	if opts.leafNotAfter.IsZero() {
		opts.leafNotAfter = year
	}
	if opts.leafDNSNames == nil {
		opts.leafDNSNames = []string{testHost}
	}
	if opts.leafSerial == 0 {
		opts.leafSerial = defaultSerial
	}

	if opts.rootNotAfter.IsZero() {
		opts.rootNotAfter = year.Add(24 * time.Hour)
	}

	root := issueCA(t, "Sentinel Test Root CA", notBefore, opts.rootNotAfter, nil)
	intermediate := issueCA(t, "Sentinel Test Intermediate CA", notBefore, opts.intermediateNotAfter, &root)

	leafKey := generateKey(t, opts.leafRSABits)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(opts.leafSerial),
		Subject:               pkix.Name{CommonName: testHost},
		NotBefore:             notBefore,
		NotAfter:              opts.leafNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              opts.leafDNSNames,
		IPAddresses:           opts.leafIPs,
	}
	leafCert := signCertificate(t, leafTmpl, intermediate.cert, publicKeyOf(leafKey), intermediate.key)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	return chain{
		root:         root,
		intermediate: intermediate,
		leaf:         issuedCert{cert: leafCert, key: ecdsaOrNil(leafKey)},
		roots:        pool,
	}
}

// issueCA generates a CA certificate. A nil parent produces a self-signed root;
// otherwise the certificate is signed by the parent.
func issueCA(t testing.TB, cn string, notBefore, notAfter time.Time, parent *issuedCert) issuedCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key for %q: %v", cn, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signer, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerKey = parent.key
	}
	var cert *x509.Certificate
	if parent == nil {
		cert = signCertificate(t, tmpl, signer, &key.PublicKey, signerKey)
	} else {
		cert = signCertificate(t, tmpl, parent.cert, &key.PublicKey, signerKey)
	}
	return issuedCert{cert: cert, key: key}
}

// signCertificate creates and re-parses a certificate so tests always work with
// the same representation the TLS stack hands to Inspect.
func signCertificate(t testing.TB, tmpl, parent *x509.Certificate, pub any, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	return cert
}

// generateKey returns an RSA key of the requested size, or a P-256 ECDSA key
// when rsaBits is zero.
func generateKey(t testing.TB, rsaBits int) crypto.Signer {
	t.Helper()
	if rsaBits > 0 {
		key, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatalf("generating %d-bit RSA key: %v", rsaBits, err)
		}
		return key
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return key
}

// publicKeyOf returns the signer's public key in the form CreateCertificate
// expects.
func publicKeyOf(signer crypto.Signer) any { return signer.Public() }

// ecdsaOrNil narrows a signer to an ECDSA key, or nil for other key types. Only
// the CA keys need to sign further certificates, so a non-ECDSA leaf key can be
// dropped.
func ecdsaOrNil(signer crypto.Signer) *ecdsa.PrivateKey {
	if key, ok := signer.(*ecdsa.PrivateKey); ok {
		return key
	}
	return nil
}

// selfSignedLeaf generates a single self-signed certificate, the shape an
// appliance or internal endpoint presents.
func selfSignedLeaf(t testing.TB, now time.Time) *x509.Certificate {
	t.Helper()
	ca := issueCA(t, testHost, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	return ca.cert
}

// stapleFor produces a signed OCSP response for the chain's leaf, as a server
// would staple it to the handshake.
//
// Parameters:
//   - t: the test.
//   - c: the chain whose leaf the response refers to.
//   - status: an ocsp.Good / ocsp.Revoked / ocsp.Unknown status.
//   - now: the reference time for ThisUpdate/NextUpdate.
//
// It returns the DER-encoded response.
func stapleFor(t testing.TB, c chain, status int, now time.Time) []byte {
	t.Helper()

	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: c.leaf.cert.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour),
		NextUpdate:   now.Add(24 * time.Hour),
		IssuerHash:   crypto.SHA256,
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-2 * time.Hour)
		tmpl.RevocationReason = ocsp.KeyCompromise
	}

	der, err := ocsp.CreateResponse(c.intermediate.cert, c.intermediate.cert, tmpl, c.intermediate.key)
	if err != nil {
		t.Fatalf("creating OCSP response: %v", err)
	}
	return der
}
