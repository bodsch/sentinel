package http

import (
	"net"
	"net/url"
	"strings"
)

// redirectStatuses is the set of status codes treated as redirects.
var redirectStatuses = map[int]struct{}{
	301: {}, // Moved Permanently
	302: {}, // Found
	303: {}, // See Other
	307: {}, // Temporary Redirect
	308: {}, // Permanent Redirect
}

// isRedirectStatus reports whether code is a redirect that carries a Location.
func isRedirectStatus(code int) bool {
	_, ok := redirectStatuses[code]
	return ok
}

// resolveLocation resolves a (possibly relative) Location header against the
// current request URL and returns the absolute next URL.
func resolveLocation(base, location string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	locURL, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(locURL).String(), nil
}

// isDowngrade reports whether following from -> to would move from HTTPS to
// plaintext HTTP, which is a security-relevant downgrade.
func isDowngrade(from, to string) bool {
	fu, err := url.Parse(from)
	if err != nil {
		return false
	}
	tu, err := url.Parse(to)
	if err != nil {
		return false
	}
	return strings.EqualFold(fu.Scheme, "https") && strings.EqualFold(tu.Scheme, "http")
}

// normalizeURL returns a canonical form used for redirect-loop detection:
// lowercased scheme and host, the default port dropped, an empty path treated as
// "/", and the fragment removed. Path and query are otherwise preserved, since
// they identify a distinct location. Query-parameter ordering is not
// canonicalised (a known, low-risk gap bounded by max_redirects).
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		u.Host = host
	} else {
		u.Host = net.JoinHostPort(host, port)
	}

	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u.String()
}
