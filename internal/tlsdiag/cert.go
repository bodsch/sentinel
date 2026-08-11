package tlsdiag

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// describeLeaf fills the identity and key fields of info from the leaf
// certificate: subject/issuer common names, serial, fingerprint, algorithms, key
// size and subject alternative names.
//
// Parameters:
//   - info: the Info to populate; modified in place.
//   - leaf: the parsed leaf certificate.
func describeLeaf(info *Info, leaf *x509.Certificate) {
	info.SubjectCN = leaf.Subject.CommonName
	info.IssuerCN = leaf.Issuer.CommonName
	info.Serial = serialHex(leaf)

	sum := sha256.Sum256(leaf.Raw)
	info.FingerprintSHA256 = hex.EncodeToString(sum[:])

	info.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	info.PublicKeyAlgorithm = leaf.PublicKeyAlgorithm.String()
	info.KeyBits = publicKeyBits(leaf)

	info.SANs, info.SANCount = subjectAltNames(leaf)
}

// serialHex renders the certificate's serial number as lowercase hexadecimal.
//
// It encodes the number's bytes rather than formatting it as an integer, which
// preserves a leading zero byte. That matters in practice: openssl, browsers and
// certificate transparency logs all display the byte form, and a serial printed
// without its leading zero cannot be pasted into a search for the certificate.
func serialHex(leaf *x509.Certificate) string {
	if leaf.SerialNumber == nil {
		return ""
	}
	b := leaf.SerialNumber.Bytes()
	if len(b) == 0 {
		// Bytes() returns an empty slice for zero, which is a malformed but
		// observable serial number.
		return "00"
	}
	return hex.EncodeToString(b)
}

// publicKeyBits reports the certificate's public key size in bits: the RSA
// modulus length, the EC curve size, or the fixed Ed25519 key size. It returns 0
// for a key type it does not recognise, so callers can distinguish "unknown"
// from a genuinely small key.
func publicKeyBits(leaf *x509.Certificate) int {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub.Curve == nil {
			return 0
		}
		params := pub.Params()
		if params == nil {
			return 0
		}
		return params.BitSize
	case ed25519.PublicKey:
		return ed25519.PublicKeySize * 8
	case *ecdh.PublicKey:
		// crypto/x509 parses an X25519 subject public key into this type; it is
		// the only ecdh curve it produces.
		if pub.Curve() == ecdh.X25519() {
			return 256
		}
		return 0
	default:
		return 0
	}
}

// subjectAltNames returns the leaf's subject alternative names as strings — DNS
// names first, then IP addresses — truncated to maxRecordedSANs, together with
// the untruncated total. Truncating bounds the memory one probed server can make
// Sentinel hold; the total is still reported so the metric stays accurate.
func subjectAltNames(leaf *x509.Certificate) (names []string, total int) {
	total = len(leaf.DNSNames) + len(leaf.IPAddresses)
	if total == 0 {
		return nil, 0
	}

	capacity := min(total, maxRecordedSANs)
	names = make([]string, 0, capacity)
	for _, dns := range leaf.DNSNames {
		if len(names) == capacity {
			return names, total
		}
		names = append(names, dns)
	}
	for _, ip := range leaf.IPAddresses {
		if len(names) == capacity {
			return names, total
		}
		names = append(names, ip.String())
	}
	return names, total
}
