package http

import "testing"

func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"http://Example.com:80/a":    "http://example.com/a",
		"https://Example.com:443/":   "https://example.com/",
		"http://host":                "http://host/",
		"https://host:8443/x#frag":   "https://host:8443/x",
		"HTTP://HOST/Path?b=2&a=1":   "http://host/Path?b=2&a=1",
		"https://host:443/p#section": "https://host/p",
	}

	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDowngrade(t *testing.T) {
	t.Parallel()

	if !isDowngrade("https://a/", "http://a/") {
		t.Error("https->http should be a downgrade")
	}
	if isDowngrade("http://a/", "https://a/") {
		t.Error("http->https is not a downgrade")
	}
	if isDowngrade("https://a/", "https://b/") {
		t.Error("https->https is not a downgrade")
	}
}

func TestResolveLocation(t *testing.T) {
	t.Parallel()

	got, err := resolveLocation("https://host/dir/page", "/other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://host/other"; got != want {
		t.Errorf("absolute-path Location: got %q, want %q", got, want)
	}

	got, err = resolveLocation("https://host/dir/page", "sub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://host/dir/sub"; got != want {
		t.Errorf("relative Location: got %q, want %q", got, want)
	}
}
