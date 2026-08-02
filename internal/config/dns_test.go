package config

import (
	"strings"
	"testing"
)

func TestValidDNSTarget(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: dns-check
    dns:
      server: 1.1.1.1
      query: example.org
      type: a
      expected:
        - 93.184.216.34
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := cfg.Targets[0].DNS
	if d == nil {
		t.Fatal("expected a DNS block")
	}
	if d.Type != "A" {
		t.Errorf("type = %q, want normalised A", d.Type)
	}
}

func TestDNSTypeDefaultsToA(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, "targets:\n  - name: x\n    dns:\n      server: 8.8.8.8:53\n      query: example.org\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Targets[0].DNS.Type; got != "A" {
		t.Errorf("default type = %q, want A", got)
	}
}

func TestDNSValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "missing server",
			yaml:    "targets:\n  - name: x\n    dns:\n      query: example.org\n",
			wantSub: "dns.server is required",
		},
		{
			name:    "missing query",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n",
			wantSub: "dns.query is required",
		},
		{
			name:    "unsupported type",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      query: example.org\n      type: SRV\n",
			wantSub: "dns.type",
		},
		{
			name:    "invalid server",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: \"http://nope\"\n      query: example.org\n",
			wantSub: "not a valid host",
		},
		{
			name:    "non-numeric port",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: \"1.1.1.1:abc\"\n      query: example.org\n",
			wantSub: "not a valid host",
		},
		{
			name:    "colon host not ipv6",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: \"a:b:c\"\n      query: example.org\n",
			wantSub: "not a valid host",
		},
		{
			name:    "empty expected value",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      query: example.org\n      expected:\n        - \"\"\n",
			wantSub: "dns.expected must not contain empty values",
		},
		{
			name:    "both http and dns",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n    dns:\n      server: 1.1.1.1\n      query: a.example\n",
			wantSub: "multiple protocol blocks",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseResolve(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}
