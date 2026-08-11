package tlsdiag

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes every sentinel_tls_* series.
//
// Unlike the protocol collectors it does not filter on a probe type: it walks
// all records and picks out those whose diagnostics implement Provider. A
// protocol therefore gains the complete TLS metric set by attaching an *Info to
// its diagnostics — no change here, and no duplicated series definitions when a
// second TLS-capable protocol arrives.
type Collector struct {
	results resultSource

	// leaf certificate
	certExpiry    *prometheus.Desc
	certNotBefore *prometheus.Desc
	certRemain    *prometheus.Desc
	certValid     *prometheus.Desc
	certSelfSign  *prometheus.Desc
	certKeyBits   *prometheus.Desc
	certSANCount  *prometheus.Desc
	certInfo      *prometheus.Desc

	// chain
	chainExpiry   *prometheus.Desc
	chainRemain   *prometheus.Desc
	chainLength   *prometheus.Desc
	chainVerified *prometheus.Desc

	// negotiated connection
	versionInfo *prometheus.Desc
	cipherInfo  *prometheus.Desc
	alpnInfo    *prometheus.Desc

	// revocation
	ocspStapled    *prometheus.Desc
	ocspInfo       *prometheus.Desc
	ocspNextUpdate *prometheus.Desc
}

// certInfoLabels are the identity labels of sentinel_tls_certificate_info. The
// subject alternative names are deliberately absent: a shared-hosting
// certificate can carry hundreds of them, which would make the label value
// kilobytes long. Their number is exported as
// sentinel_tls_certificate_san_count instead.
var certInfoLabels = []string{
	"subject_cn",
	"issuer_cn",
	"serial",
	"fingerprint_sha256",
	"signature_algorithm",
	"public_key_algorithm",
}

// NewCollector builds the TLS metrics collector over the given result source.
func NewCollector(results resultSource) *Collector {
	base := metrics.BaseLabelNames
	desc := func(name, help string, extra ...string) *prometheus.Desc {
		labels := base
		if len(extra) > 0 {
			labels = append(append([]string{}, base...), extra...)
		}
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, labels, nil)
	}

	return &Collector{
		results: results,

		certExpiry:    desc("tls_certificate_expiry_timestamp_seconds", "Unix timestamp when the leaf certificate expires."),
		certNotBefore: desc("tls_certificate_not_before_timestamp_seconds", "Unix timestamp from which the leaf certificate is valid."),
		certRemain:    desc("tls_certificate_remaining_days", "Whole days until the leaf certificate expires; negative if expired."),
		certValid:     desc("tls_certificate_valid", "1 if the certificate passed Sentinel's checks, else 0."),
		certSelfSign:  desc("tls_certificate_self_signed", "1 if the leaf certificate is self-signed, else 0."),
		certKeyBits:   desc("tls_certificate_key_bits", "Public key size of the leaf certificate in bits; 0 if the key type is unknown."),
		certSANCount:  desc("tls_certificate_san_count", "Number of subject alternative names in the leaf certificate."),
		certInfo:      desc("tls_certificate_info", "Leaf certificate identity. Always 1; the labels carry the data.", certInfoLabels...),

		chainExpiry:   desc("tls_chain_earliest_expiry_timestamp_seconds", "Unix timestamp of the earliest expiry across the certificate chain."),
		chainRemain:   desc("tls_chain_earliest_remaining_days", "Whole days until the first certificate in the chain expires; negative if expired."),
		chainLength:   desc("tls_chain_length", "Number of certificates in the evaluated chain."),
		chainVerified: desc("tls_chain_verified", "1 if the chain verified against the configured trust roots, else 0."),

		versionInfo: desc("tls_version_info", "Negotiated TLS version. Always 1; the version label carries the data.", "version"),
		cipherInfo:  desc("tls_cipher_info", "Negotiated cipher suite. Always 1; the cipher label carries the data.", "cipher"),
		alpnInfo:    desc("tls_alpn_info", "Application protocol negotiated via ALPN. Always 1; the protocol label carries the data.", "protocol"),

		ocspStapled:    desc("tls_ocsp_stapled", "1 if the server stapled an OCSP response to the handshake, else 0."),
		ocspInfo:       desc("tls_ocsp_info", "Status of the stapled OCSP response. Always 1; the status label carries the data.", "status"),
		ocspNextUpdate: desc("tls_ocsp_next_update_timestamp_seconds", "Unix timestamp when the stapled OCSP response goes stale."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs() {
		ch <- d
	}
}

// descs returns every descriptor the collector can emit.
func (c *Collector) descs() []*prometheus.Desc {
	return []*prometheus.Desc{
		c.certExpiry, c.certNotBefore, c.certRemain, c.certValid,
		c.certSelfSign, c.certKeyBits, c.certSANCount, c.certInfo,
		c.chainExpiry, c.chainRemain, c.chainLength, c.chainVerified,
		c.versionInfo, c.cipherInfo, c.alpnInfo,
		c.ocspStapled, c.ocspInfo, c.ocspNextUpdate,
	}
}

// Collect implements prometheus.Collector. Records without TLS information are
// skipped entirely, so a plain HTTP target emits no sentinel_tls_* series at all
// rather than a misleading zero.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		provider, ok := rec.Result.Diagnostics.(Provider)
		if !ok {
			continue
		}
		info := provider.TLSDiagnostics()
		if info == nil {
			continue
		}
		c.collectOne(ch, metrics.BaseLabelValues(rec), info)
	}
}

// collectOne emits every series for a single record's TLS info.
//
// Parameters:
//   - ch: the channel Collect was handed.
//   - labels: the base label values for the record.
//   - info: the record's TLS diagnostics; never nil.
func (c *Collector) collectOne(ch chan<- prometheus.Metric, labels []string, info *Info) {
	gauge := func(d *prometheus.Desc, v float64, extra ...string) {
		values := labels
		if len(extra) > 0 {
			values = append(append([]string{}, labels...), extra...)
		}
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, values...)
	}

	gauge(c.certExpiry, float64(info.ExpiresAt.Unix()))
	gauge(c.certRemain, float64(info.RemainingDays))
	gauge(c.certValid, boolValue(info.Valid))
	gauge(c.certSelfSign, boolValue(info.SelfSigned))
	gauge(c.certKeyBits, float64(info.KeyBits))
	gauge(c.certSANCount, float64(info.SANCount))
	if !info.NotBefore.IsZero() {
		gauge(c.certNotBefore, float64(info.NotBefore.Unix()))
	}

	gauge(c.chainLength, float64(info.ChainLength))
	gauge(c.chainVerified, boolValue(info.ChainVerified))
	if !info.ChainEarliestExpiry.IsZero() {
		gauge(c.chainExpiry, float64(info.ChainEarliestExpiry.Unix()))
		gauge(c.chainRemain, float64(info.ChainEarliestRemainingDays))
	}

	gauge(c.certInfo, 1,
		info.SubjectCN,
		info.IssuerCN,
		info.Serial,
		info.FingerprintSHA256,
		info.SignatureAlgorithm,
		info.PublicKeyAlgorithm,
	)

	// Info series carry their data in a label, so they are emitted only when
	// that data exists. Emitting an empty label value would create a series that
	// says nothing and lingers next to the real one after a change.
	if info.VersionName != "" {
		gauge(c.versionInfo, 1, info.VersionName)
	}
	if info.CipherName != "" {
		gauge(c.cipherInfo, 1, info.CipherName)
	}
	if info.ALPN != "" {
		gauge(c.alpnInfo, 1, info.ALPN)
	}

	gauge(c.ocspStapled, boolValue(info.OCSP != nil))
	if info.OCSP != nil {
		gauge(c.ocspInfo, 1, info.OCSP.Status)
		if !info.OCSP.NextUpdate.IsZero() {
			gauge(c.ocspNextUpdate, float64(info.OCSP.NextUpdate.Unix()))
		}
	}
}

// boolValue maps a boolean diagnostic to the 1/0 convention Prometheus gauges
// use for flags.
func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
