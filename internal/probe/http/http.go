// Package http implements the HTTP/HTTPS probe: the feature-rich core of
// Sentinel 0.1.
//
// Key behaviours (see the design docs for the rationale):
//   - a fresh connection per run (keep-alives disabled) so every DNS/TCP/TLS
//     phase is measured on every run;
//   - per-phase timing via net/http/httptrace;
//   - manual redirect handling with loop, limit and HTTPS->HTTP downgrade
//     detection; phase timings describe the final hop, total duration covers all
//     hops;
//   - manual TLS certificate inspection (expiry, hostname, remaining days);
//   - a single total timeout applied over the whole run via the context;
//   - HTTP_PROXY/HTTPS_PROXY honoured via the environment.
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/validator"
	"bodsch.me/sentinel/pkg/version"
)

// ProbeType is the protocol identifier for HTTP probes.
const ProbeType = "http"

// Options carries the fully-resolved settings for one HTTP target. The caller
// (the scheduler) builds it from the validated configuration, keeping this
// package independent of the config package.
type Options struct {
	// Name is the target name (for reference/logging).
	Name string
	// Method is the HTTP method (GET, HEAD, POST, PUT, PATCH or DELETE).
	Method string
	// URL is the target URL.
	URL string
	// Timeout is the total per-run timeout.
	Timeout time.Duration
	// FollowRedirects controls whether redirects are followed.
	FollowRedirects bool
	// MaxRedirects is the maximum number of redirects to follow.
	MaxRedirects int
	// MaxBodyBytes caps how many response body bytes are read. A value of zero
	// (or less) disables the cap: the full body is read into memory, stopped
	// only by the probe timeout. The resident cost is therefore bounded by
	// timeout x bandwidth, not by any byte limit, so an uncapped probe against a
	// large or hostile server can consume substantial memory — use only for
	// trusted targets.
	MaxBodyBytes int64
	// ExpectStatus is the expected status code (already defaulted, e.g. 200).
	ExpectStatus int
	// BodyRegex are response-body patterns that must all match.
	BodyRegex []string
	// Headers are exact response-header expectations.
	Headers map[string]string

	// RequestHeaders are headers sent with the request. A "Host" key sets the
	// request host. For security they are applied only to the target's own host,
	// not carried across a redirect to a different host.
	RequestHeaders map[string]string
	// BasicAuthUser/BasicAuthPass, when the user is non-empty, add an HTTP Basic
	// Authorization header.
	BasicAuthUser string
	BasicAuthPass string
	// BearerToken, when non-empty, adds an "Authorization: Bearer <token>" header.
	BearerToken string
	// Body is the request body sent with the initial request. Redirects are
	// followed as GET with no body.
	Body string
}

// Prober runs HTTP checks for a single target. It satisfies probe.Prober.
type Prober struct {
	name            string
	method          string
	url             string
	timeout         time.Duration
	followRedirects bool
	maxRedirects    int
	maxBodyBytes    int64
	userAgent       string
	requestHeaders  map[string]string
	basicUser       string
	basicPass       string
	bearerToken     string
	body            string
	origin          string // canonical scheme://host:port of the target URL
	validators      []validator.Validator
	transport       *http.Transport
}

// compile-time check.
var _ probe.Prober = (*Prober)(nil)

// New builds a Prober from resolved options. It returns an error only if a body
// regex fails to compile (configuration validation compiles them once already,
// so this is defensive).
func New(opts Options) (*Prober, error) {
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("http probe %q: timeout must be greater than zero", opts.Name)
	}

	validators, err := buildValidators(opts)
	if err != nil {
		return nil, err
	}

	p := &Prober{
		name:            opts.Name,
		method:          opts.Method,
		url:             opts.URL,
		timeout:         opts.Timeout,
		followRedirects: opts.FollowRedirects,
		maxRedirects:    opts.MaxRedirects,
		maxBodyBytes:    opts.MaxBodyBytes,
		userAgent:       "sentinel/" + version.Version,
		requestHeaders:  opts.RequestHeaders,
		basicUser:       opts.BasicAuthUser,
		basicPass:       opts.BasicAuthPass,
		bearerToken:     strings.TrimSpace(opts.BearerToken),
		body:            opts.Body,
		origin:          originKey(opts.URL),
		validators:      validators,
		transport:       newTransport(),
	}
	return p, nil
}

// originKey returns a canonical scheme://host:port key for same-origin checks:
// scheme and host lowercased, any trailing dot on the host removed, and the port
// defaulted from the scheme. Custom headers and credentials are forwarded across
// a redirect only when the hop's originKey equals the target's, so they never
// reach a different host, port, or scheme — the last of which also stops
// credentials being resent in clear after an https->http downgrade. It matches
// the host/port canonicalisation used by normalizeURL for redirect-loop
// detection, keeping the two host-identity notions consistent.
func originKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + host + ":" + port
}

// applyRequestHeaders adds the configured request headers and authentication to
// req. A "Host" header maps to req.Host (the transport ignores it in req.Header).
// Auth sets the Authorization header; config validation guarantees at most one of
// basic auth, bearer token, or an explicit Authorization header is configured.
func (p *Prober) applyRequestHeaders(req *http.Request, hasBody bool) {
	for k, v := range p.requestHeaders {
		if http.CanonicalHeaderKey(k) == "Host" {
			req.Host = v
			continue
		}
		// Content-Type describes a body; skip it on a bodyless request (e.g. a
		// redirect followed as GET) so the request does not declare a type for a
		// body it no longer carries.
		if !hasBody && http.CanonicalHeaderKey(k) == "Content-Type" {
			continue
		}
		req.Header.Set(k, v)
	}
	switch {
	case p.basicUser != "":
		req.SetBasicAuth(p.basicUser, p.basicPass)
	case p.bearerToken != "":
		req.Header.Set("Authorization", "Bearer "+p.bearerToken)
	}
}

// buildValidators turns the resolved expectations into an ordered validator
// list. Status is checked first (its own failure reason), then body, then
// headers.
func buildValidators(opts Options) ([]validator.Validator, error) {
	expectStatus := opts.ExpectStatus
	if expectStatus == 0 {
		expectStatus = 200 // sensible default if the caller left it unset
	}
	vs := []validator.Validator{validator.NewStatus(expectStatus)}

	if len(opts.BodyRegex) > 0 {
		patterns := make([]*regexp.Regexp, 0, len(opts.BodyRegex))
		for _, raw := range opts.BodyRegex {
			re, err := regexp.Compile(raw)
			if err != nil {
				return nil, fmt.Errorf("http probe %q: body_regex %q: %w", opts.Name, raw, err)
			}
			patterns = append(patterns, re)
		}
		vs = append(vs, validator.NewBodyRegex(patterns))
	}

	if len(opts.Headers) > 0 {
		vs = append(vs, validator.NewHeader(opts.Headers))
	}

	return vs, nil
}

// Type implements probe.Prober.
func (p *Prober) Type() string { return ProbeType }

// Probe implements probe.Prober. It applies the target's total timeout, runs the
// request (following redirects manually), and returns a typed Result. It never
// returns an error: a failed check is a successful execution with Success=false.
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

// run executes the request, following redirects manually, and returns the
// diagnostics gathered so far, the final hop's timings, and the failure reason
// (ReasonNone on success).
func (p *Prober) run(ctx context.Context) (*Diagnostics, probe.Timings, probe.FailureReason) {
	diag := &Diagnostics{}
	var timings probe.Timings

	current := p.url
	visited := map[string]struct{}{normalizeURL(current): {}}

	// method and body apply to the initial request; a redirect resets them to a
	// bodyless GET (see the redirect branch below).
	method := p.method
	bodyStr := p.body

	for {
		var reqBody io.Reader
		if bodyStr != "" {
			reqBody = strings.NewReader(bodyStr)
		}
		req, err := http.NewRequestWithContext(ctx, method, current, reqBody)
		if err != nil {
			// The URL was validated at config load, so this is unexpected.
			return diag, timings, probe.ReasonNetworkError
		}
		req.Header.Set("User-Agent", p.userAgent)

		// Apply custom headers and auth only to the target's own origin
		// (scheme+host+port): a redirect to a different origin must not receive
		// the credentials or headers, which would leak them to a third party (or
		// resend them in clear after an https->http downgrade).
		if originKey(current) == p.origin {
			p.applyRequestHeaders(req, bodyStr != "")
		}

		tr := newHopTrace()
		req = req.WithContext(traceContext(req.Context(), tr))

		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			return diag, timings, classifyError(err)
		}

		// Inspect TLS on every hop, not only the final one: an expired or
		// hostname-mismatched certificate on an intermediate redirect hop is a
		// real failure and must not be masked by a healthy final target.
		if resp.TLS != nil {
			info, tlsReason := inspectTLS(resp.TLS, hostname(current), time.Now())
			diag.TLS = info
			if tlsReason != probe.ReasonNone {
				timings = tr.timings(time.Now())
				_ = resp.Body.Close()
				diag.FinalURL = current
				diag.StatusCode = resp.StatusCode
				return diag, timings, tlsReason
			}
		}

		// Follow a redirect if configured to.
		if p.followRedirects && isRedirectStatus(resp.StatusCode) && resp.Header.Get("Location") != "" {
			location := resp.Header.Get("Location")
			// Keep-alives are disabled, so closing (without reading the body) is
			// enough and avoids reading an unbounded redirect body off the wire.
			_ = resp.Body.Close()

			next, err := resolveLocation(current, location)
			if err != nil {
				return diag, timings, probe.ReasonNetworkError
			}

			// The terminating conditions describe a redirect we refuse to
			// follow, so diag.Redirects records only the hops actually followed.
			if isDowngrade(current, next) {
				return diag, timings, probe.ReasonDowngrade
			}
			if len(diag.Redirects) >= p.maxRedirects {
				return diag, timings, probe.ReasonRedirectLimit
			}
			if _, seen := visited[normalizeURL(next)]; seen {
				return diag, timings, probe.ReasonRedirectLoop
			}

			diag.Redirects = append(diag.Redirects, RedirectStep{URL: current, StatusCode: resp.StatusCode})
			visited[normalizeURL(next)] = struct{}{}
			current = next
			// Drop the request body on any redirect — it is never re-sent, which
			// avoids duplicate side-effects and (with the origin guard above)
			// cross-origin leaks. Preserve GET and HEAD; downgrade body-carrying
			// or side-effecting methods (POST/PUT/PATCH/DELETE) to GET so the
			// redirect target is only read, not mutated. This matches common
			// client behaviour for 301/302/303; a target that needs the method
			// preserved across a redirect should set follow_redirects: false.
			bodyStr = ""
			if method != http.MethodGet && method != http.MethodHead {
				method = http.MethodGet
			}
			continue
		}

		// Final response.
		diag.FinalURL = current
		diag.StatusCode = resp.StatusCode

		body, readErr := readCapped(resp.Body, p.maxBodyBytes)
		downloadEnd := time.Now()
		// Close without draining. With keep-alives disabled the connection is
		// not reused, so when a cap applies, reading the remaining (potentially
		// unbounded) body would only defeat the max_body_bytes cap for no
		// benefit. When uncapped (max_body_bytes: 0) readCapped already consumed
		// the whole body, so this close merely releases the connection.
		_ = resp.Body.Close()
		timings = tr.timings(downloadEnd)

		if readErr != nil {
			return diag, timings, classifyError(readErr)
		}

		// TLS was already inspected above (per-hop), so a bad certificate has
		// already returned. Validate the response body/headers.
		vr := &validator.Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       body,
		}
		for _, v := range p.validators {
			if out := v.Validate(vr); !out.OK {
				return diag, timings, out.Reason
			}
		}

		return diag, timings, probe.ReasonNone
	}
}

// readCapped reads at most max bytes from r. Bytes beyond the cap are left on
// the connection, which is then closed by the caller. A max of zero (or less)
// means "no cap": the full body is read into memory, stopped only by the
// probe's context deadline (the per-target timeout) — so the buffer can grow to
// roughly timeout x bandwidth, not to any fixed limit. This opt-out is for
// targets where the true full-body transfer time matters and the operator
// accepts the unbounded memory cost.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return io.ReadAll(r)
	}
	return io.ReadAll(io.LimitReader(r, max))
}
