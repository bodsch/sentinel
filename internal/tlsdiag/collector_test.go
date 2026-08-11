package tlsdiag

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

type fakeResults struct{ recs []store.Record }

func (f fakeResults) Snapshot() []store.Record { return f.recs }

// tlsDiagnostics is a minimal probe.Diagnostics that carries TLS information,
// standing in for a protocol package's own type.
type tlsDiagnostics struct{ info *Info }

func (*tlsDiagnostics) ProbeType() string       { return "fake" }
func (d *tlsDiagnostics) TLSDiagnostics() *Info { return d.info }

// plainDiagnostics carries no TLS information at all — the shape of a protocol
// that never negotiates TLS.
type plainDiagnostics struct{}

func (*plainDiagnostics) ProbeType() string { return "plain" }

// gatherValue returns the value of the named series whose labels include want.
func gatherValue(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsContain(m.GetLabel(), want) {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func labelsContain(have []*dto.LabelPair, want map[string]string) bool {
	index := make(map[string]string, len(have))
	for _, lp := range have {
		index[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if index[k] != v {
			return false
		}
	}
	return true
}

// fullInfo is a populated diagnostic covering every series the collector emits.
func fullInfo() *Info {
	return &Info{
		ExpiresAt:                  time.Unix(2_000_000, 0),
		NotBefore:                  time.Unix(1_000_000, 0),
		RemainingDays:              42,
		HostnameValid:              true,
		Valid:                      true,
		SelfSigned:                 false,
		ChainLength:                3,
		ChainVerified:              true,
		ChainEarliestExpiry:        time.Unix(1_500_000, 0),
		ChainEarliestRemainingDays: 17,
		Version:                    tls.VersionTLS13,
		VersionName:                "TLS 1.3",
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
		CipherName:                 "TLS_AES_128_GCM_SHA256",
		ALPN:                       "h2",
		SubjectCN:                  "example.org",
		IssuerCN:                   "Let's Encrypt R3",
		Serial:                     "1267",
		FingerprintSHA256:          "abc123",
		SignatureAlgorithm:         "SHA256-RSA",
		PublicKeyAlgorithm:         "ECDSA",
		KeyBits:                    256,
		SANCount:                   2,
		OCSP: &OCSPInfo{
			Status:     StatusGood,
			NextUpdate: time.Unix(2_500_000, 0),
		},
	}
}

func registerWith(t *testing.T, recs []store.Record) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))
	return reg
}

func TestCollector(t *testing.T) {
	t.Parallel()

	rec := store.Record{
		Target: "site", Type: "http",
		Labels: map[string]string{"service": "web"},
		Result: probe.Result{Success: true, Diagnostics: &tlsDiagnostics{info: fullInfo()}},
	}
	reg := registerWith(t, []store.Record{rec})
	base := map[string]string{"target": "site", "service": "web"}

	checks := []struct {
		name   string
		labels map[string]string
		want   float64
	}{
		{name: "sentinel_tls_certificate_expiry_timestamp_seconds", want: 2_000_000},
		{name: "sentinel_tls_certificate_not_before_timestamp_seconds", want: 1_000_000},
		{name: "sentinel_tls_certificate_remaining_days", want: 42},
		{name: "sentinel_tls_certificate_valid", want: 1},
		{name: "sentinel_tls_certificate_self_signed", want: 0},
		{name: "sentinel_tls_certificate_key_bits", want: 256},
		{name: "sentinel_tls_certificate_san_count", want: 2},
		{name: "sentinel_tls_chain_earliest_expiry_timestamp_seconds", want: 1_500_000},
		{name: "sentinel_tls_chain_earliest_remaining_days", want: 17},
		{name: "sentinel_tls_chain_length", want: 3},
		{name: "sentinel_tls_chain_verified", want: 1},
		{name: "sentinel_tls_ocsp_stapled", want: 1},
		{name: "sentinel_tls_ocsp_next_update_timestamp_seconds", want: 2_500_000},
		{name: "sentinel_tls_version_info", labels: map[string]string{"version": "TLS 1.3"}, want: 1},
		{name: "sentinel_tls_cipher_info", labels: map[string]string{"cipher": "TLS_AES_128_GCM_SHA256"}, want: 1},
		{name: "sentinel_tls_alpn_info", labels: map[string]string{"protocol": "h2"}, want: 1},
		{name: "sentinel_tls_ocsp_info", labels: map[string]string{"status": "good"}, want: 1},
		{
			name: "sentinel_tls_certificate_info",
			labels: map[string]string{
				"subject_cn":           "example.org",
				"issuer_cn":            "Let's Encrypt R3",
				"serial":               "1267",
				"fingerprint_sha256":   "abc123",
				"signature_algorithm":  "SHA256-RSA",
				"public_key_algorithm": "ECDSA",
			},
			want: 1,
		},
	}

	for _, c := range checks {
		labels := make(map[string]string, len(base)+len(c.labels))
		for k, v := range base {
			labels[k] = v
		}
		for k, v := range c.labels {
			labels[k] = v
		}
		if v, ok := gatherValue(t, reg, c.name, labels); !ok || v != c.want {
			t.Errorf("%s = %v ok=%v, want %v", c.name, v, ok, c.want)
		}
	}
}

// TestCollectorSkipsRecordsWithoutTLS covers the vanishing semantics: a target
// that never negotiated TLS must produce no certificate series at all, rather
// than zeros that read like a real (and alarming) measurement.
func TestCollectorSkipsRecordsWithoutTLS(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		// Diagnostics that do not implement Provider at all.
		{Target: "plain", Type: "plain", Result: probe.Result{Diagnostics: &plainDiagnostics{}}},
		// Implements Provider but has no TLS to report.
		{Target: "notls", Type: "http", Result: probe.Result{Diagnostics: &tlsDiagnostics{info: nil}}},
		// No diagnostics whatsoever.
		{Target: "empty", Type: "dns", Result: probe.Result{Diagnostics: nil}},
	}
	reg := registerWith(t, recs)

	for _, target := range []string{"plain", "notls", "empty"} {
		for _, name := range []string{
			"sentinel_tls_certificate_valid",
			"sentinel_tls_chain_length",
			"sentinel_tls_ocsp_stapled",
		} {
			if _, ok := gatherValue(t, reg, name, map[string]string{"target": target}); ok {
				t.Errorf("target %q without TLS produced %s", target, name)
			}
		}
	}
}

// TestCollectorOmitsUnsetOptionalSeries asserts that series whose data is
// missing are left out entirely instead of being emitted with an empty label or
// a meaningless zero timestamp.
func TestCollectorOmitsUnsetOptionalSeries(t *testing.T) {
	t.Parallel()

	// A handshake that failed before any of this could be determined.
	info := &Info{ExpiresAt: time.Unix(2_000_000, 0), ChainLength: 1}
	rec := store.Record{
		Target: "sparse", Type: "http",
		Result: probe.Result{Diagnostics: &tlsDiagnostics{info: info}},
	}
	reg := registerWith(t, []store.Record{rec})
	target := map[string]string{"target": "sparse"}

	for _, name := range []string{
		"sentinel_tls_version_info",
		"sentinel_tls_cipher_info",
		// No ALPN was offered or agreed — the common case for the HTTP probe,
		// whose transport does not negotiate it.
		"sentinel_tls_alpn_info",
		"sentinel_tls_ocsp_info",
		"sentinel_tls_ocsp_next_update_timestamp_seconds",
		"sentinel_tls_certificate_not_before_timestamp_seconds",
		"sentinel_tls_chain_earliest_expiry_timestamp_seconds",
	} {
		if _, ok := gatherValue(t, reg, name, target); ok {
			t.Errorf("%s emitted without data behind it", name)
		}
	}

	// What is known must still be reported, including the explicit "nothing was
	// stapled" signal.
	if v, ok := gatherValue(t, reg, "sentinel_tls_ocsp_stapled", target); !ok || v != 0 {
		t.Errorf("ocsp_stapled = %v ok=%v, want 0", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_certificate_valid", target); !ok || v != 0 {
		t.Errorf("certificate_valid = %v ok=%v, want 0", v, ok)
	}
}

// TestCollectorIsProtocolAgnostic asserts the collector serves any probe type
// whose diagnostics carry TLS information — the property that lets a future
// tls: or TLS-enabled tcp probe reuse these series unchanged.
func TestCollectorIsProtocolAgnostic(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		{Target: "web", Type: "http", Result: probe.Result{Diagnostics: &tlsDiagnostics{info: fullInfo()}}},
		{Target: "ldaps", Type: "tcp", Result: probe.Result{Diagnostics: &tlsDiagnostics{info: fullInfo()}}},
	}
	reg := registerWith(t, recs)

	for _, target := range []string{"web", "ldaps"} {
		if v, ok := gatherValue(t, reg, "sentinel_tls_certificate_valid", map[string]string{"target": target}); !ok || v != 1 {
			t.Errorf("target %q: certificate_valid = %v ok=%v, want 1", target, v, ok)
		}
	}
}

// TestCollectorDescribeCoversEveryMetric guards against a descriptor being added
// to Collect but forgotten in Describe, which would break registration checks.
func TestCollectorDescribeCoversEveryMetric(t *testing.T) {
	t.Parallel()

	c := NewCollector(fakeResults{})
	ch := make(chan *prometheus.Desc, len(c.descs())+8)
	c.Describe(ch)
	close(ch)

	seen := 0
	for range ch {
		seen++
	}
	if seen != len(c.descs()) {
		t.Errorf("Describe emitted %d descriptors, want %d", seen, len(c.descs()))
	}

	// Every series the collector can emit must reach the registry.
	rec := store.Record{Target: "site", Type: "http", Result: probe.Result{Diagnostics: &tlsDiagnostics{info: fullInfo()}}}
	reg := registerWith(t, []store.Record{rec})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != len(c.descs()) {
		t.Errorf("gathered %d metric families, want %d", len(mfs), len(c.descs()))
	}
}
