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
			wantSub: "dns.server (or dns.servers) is required",
		},
		{
			name:    "missing query",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n",
			wantSub: "dns.query is required",
		},
		{
			name:    "unsupported type",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      query: example.org\n      type: PTR\n",
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
			name:    "server and servers together",
			yaml:    "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      servers: [8.8.8.8]\n      query: example.org\n",
			wantSub: "dns.server and dns.servers are mutually exclusive",
		},
		{
			name:    "servers entry invalid",
			yaml:    "targets:\n  - name: x\n    dns:\n      servers: [1.1.1.1, \"http://nope\"]\n      query: example.org\n",
			wantSub: "dns.servers[1] \"http://nope\" is not a valid host or host:port",
		},
		{
			name:    "servers duplicate with explicit default port",
			yaml:    "targets:\n  - name: x\n    dns:\n      servers: [1.1.1.1, \"1.1.1.1:53\"]\n      query: example.org\n",
			wantSub: "dns.servers[1] \"1.1.1.1:53\" repeats dns.servers[0]",
		},
		{
			name:    "servers too many",
			yaml:    "targets:\n  - name: x\n    dns:\n      servers: [10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9, 10.0.0.10, 10.0.0.11]\n      query: example.org\n",
			wantSub: "dns.servers has 11 entries, at most 10 are allowed",
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

// TestDNSCNAMEAndSRVValid covers the record types added after 0.2, including the
// case-insensitive type name and an SRV expectation with irregular spacing.
func TestDNSCNAMEAndSRVValid(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: cname
    dns:
      server: 1.1.1.1
      query: www.example.org
      type: cname
      expected: [example.org]
  - name: srv
    dns:
      server: 1.1.1.1
      query: _sip._tcp.example.org
      type: SRV
      expected:
        - "10 5 5060 sip.example.org"
        - "20  0  5061  sip2.example.org."
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Targets[0].DNS.Type; got != "CNAME" {
		t.Errorf("type = %q, want CNAME", got)
	}
}

// TestDNSSRVExpectedMalformed rejects SRV expectations that could never match a
// real answer, naming the offending entry.
func TestDNSSRVExpectedMalformed(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"target only":        "sip.example.org",
		"port and target":    "5060 sip.example.org",
		"five fields":        "10 5 5060 sip.example.org extra",
		"non-numeric weight": "10 x 5060 sip.example.org",
		"port out of range":  "10 5 70000 sip.example.org",
		"negative priority":  "-1 5 5060 sip.example.org",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			yaml := "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      query: _sip._tcp.example.org\n      type: srv\n      expected: [\"" + value + "\"]\n"
			_, err := parseResolve(t, yaml)
			if err == nil || !strings.Contains(err.Error(), "dns.expected[0]") {
				t.Fatalf("err = %v, want a dns.expected[0] error", err)
			}
		})
	}
}

// TestDNSSRVFormatOnlyCheckedForSRV makes sure the SRV form is not imposed on
// other types, where a single token is the normal expected value.
func TestDNSSRVFormatOnlyCheckedForSRV(t *testing.T) {
	t.Parallel()

	_, err := parseResolve(t, "targets:\n  - name: x\n    dns:\n      server: 1.1.1.1\n      query: example.org\n      type: TXT\n      expected: [\"10 5 not-srv\"]\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDNSResolvedServers(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: single
    dns:
      server: 1.1.1.1
      query: example.org
  - name: compare
    dns:
      servers: [" 1.1.1.1 ", "9.9.9.9:53", "[2620:fe::fe]:53"]
      query: example.org
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Targets[0].DNS.ResolvedServers(); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("single server resolved to %v, want [1.1.1.1]", got)
	}
	got := cfg.Targets[1].DNS.ResolvedServers()
	want := []string{"1.1.1.1", "9.9.9.9:53", "[2620:fe::fe]:53"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("servers resolved to %v, want %v", got, want)
	}
}
