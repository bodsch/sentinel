package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bodsch.me/sentinel/internal/config"
)

// writeSecret writes content to a fresh file in a per-test directory with
// owner-only permissions, as an operator would deploy a credential.
func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}
	return path
}

// TestReadSecretFile covers the accepted shapes of a secret file and every
// rejection, including the guarantee that an error never echoes the content.
func TestReadSecretFile(t *testing.T) {
	t.Parallel()

	t.Run("trims trailing newline and surrounding whitespace", func(t *testing.T) {
		t.Parallel()
		got, err := readSecretFile(writeSecret(t, "  s3cret\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "s3cret" {
			t.Errorf("secret = %q, want s3cret", got)
		}
	})

	t.Run("windows line ending", func(t *testing.T) {
		t.Parallel()
		got, err := readSecretFile(writeSecret(t, "tok\r\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "tok" {
			t.Errorf("secret = %q, want tok", got)
		}
	})

	t.Run("inner whitespace is kept", func(t *testing.T) {
		t.Parallel()
		got, err := readSecretFile(writeSecret(t, "pass word\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "pass word" {
			t.Errorf("secret = %q, want %q", got, "pass word")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := readSecretFile(filepath.Join(t.TempDir(), "absent"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want a not-exist error", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		_, err := readSecretFile(writeSecret(t, ""))
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("err = %v, want 'is empty'", err)
		}
	})

	t.Run("whitespace-only file", func(t *testing.T) {
		t.Parallel()
		_, err := readSecretFile(writeSecret(t, " \n\t\n"))
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("err = %v, want 'is empty'", err)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		t.Parallel()
		content := strings.Repeat("x", maxSecretFileBytes+1)
		_, err := readSecretFile(writeSecret(t, content))
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("err = %v, want 'larger than'", err)
		}
		if err != nil && strings.Contains(err.Error(), "xxxx") {
			t.Error("error message leaks file content")
		}
	})

	t.Run("exactly at the limit", func(t *testing.T) {
		t.Parallel()
		content := strings.Repeat("x", maxSecretFileBytes)
		got, err := readSecretFile(writeSecret(t, content))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != maxSecretFileBytes {
			t.Errorf("len = %d, want %d", len(got), maxSecretFileBytes)
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		if _, err := readSecretFile(t.TempDir()); err == nil {
			t.Error("expected an error for a directory")
		}
	})
}

// httpTarget builds a resolved HTTP target for the options mapping tests.
func httpTarget(h *config.HTTPConfig) config.Target {
	return config.Target{Name: "t", HTTP: h}
}

// TestHTTPOptionsSecretFiles verifies that file-based credentials reach the
// prober options, and that a broken file stops startup with an error naming the
// target and the field but not the credential.
func TestHTTPOptionsSecretFiles(t *testing.T) {
	t.Parallel()

	caches := func() (map[string]*x509.CertPool, map[string]*tls.Certificate) {
		return map[string]*x509.CertPool{}, map[string]*tls.Certificate{}
	}

	t.Run("bearer token from file", func(t *testing.T) {
		t.Parallel()
		ca, cc := caches()
		opts, err := httpOptions(httpTarget(&config.HTTPConfig{
			URL:             "https://a.example",
			BearerTokenFile: writeSecret(t, "tok-from-file\n"),
		}), ca, cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.BearerToken != "tok-from-file" {
			t.Errorf("BearerToken = %q, want tok-from-file", opts.BearerToken)
		}
	})

	t.Run("basic password from file", func(t *testing.T) {
		t.Parallel()
		ca, cc := caches()
		opts, err := httpOptions(httpTarget(&config.HTTPConfig{
			URL: "https://a.example",
			BasicAuth: &config.BasicAuth{
				Username:     "alice",
				PasswordFile: writeSecret(t, "pw-from-file\n"),
			},
		}), ca, cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.BasicAuthUser != "alice" || opts.BasicAuthPass != "pw-from-file" {
			t.Errorf("basic auth = %q/%q, want alice/pw-from-file", opts.BasicAuthUser, opts.BasicAuthPass)
		}
	})

	t.Run("inline credentials are untouched", func(t *testing.T) {
		t.Parallel()
		ca, cc := caches()
		opts, err := httpOptions(httpTarget(&config.HTTPConfig{
			URL:       "https://a.example",
			BasicAuth: &config.BasicAuth{Username: "bob", Password: "inline"},
		}), ca, cc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.BasicAuthPass != "inline" {
			t.Errorf("BasicAuthPass = %q, want inline", opts.BasicAuthPass)
		}
	})

	t.Run("missing token file", func(t *testing.T) {
		t.Parallel()
		ca, cc := caches()
		_, err := httpOptions(httpTarget(&config.HTTPConfig{
			URL:             "https://a.example",
			BearerTokenFile: filepath.Join(t.TempDir(), "absent"),
		}), ca, cc)
		if err == nil || !strings.Contains(err.Error(), "bearer_token_file") || !strings.Contains(err.Error(), `"t"`) {
			t.Errorf("err = %v, want an error naming the target and bearer_token_file", err)
		}
	})

	t.Run("empty password file", func(t *testing.T) {
		t.Parallel()
		ca, cc := caches()
		_, err := httpOptions(httpTarget(&config.HTTPConfig{
			URL:       "https://a.example",
			BasicAuth: &config.BasicAuth{Username: "alice", PasswordFile: writeSecret(t, "\n")},
		}), ca, cc)
		if err == nil || !strings.Contains(err.Error(), "password_file") {
			t.Errorf("err = %v, want an error naming password_file", err)
		}
	})
}
