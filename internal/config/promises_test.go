package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFleetWideBodyCapOptOutRejected is the promise configuration.md makes about
// max_body_bytes: the no-cap opt-out is a per-target decision and "can never
// blanket the whole fleet from one line".
//
// The cap is Sentinel's only bound on how much of a response body it reads into
// memory. Because applyDefaults copies an unset target field from the defaults
// block, a `max_body_bytes: 0` there would be inherited by every target that did
// not set its own — so one line would silently uncap the entire fleet. The next
// target that answers with a multi-gigabyte body (a misrouted file download, a
// log endpoint, a `/dump` handler) would then be read fully into the probe
// worker's memory, at the configured interval, until the process is OOM-killed.
// Losing the monitoring during an incident is worse than losing the measurement.
//
// The per-target opt-out must still work — a target whose body genuinely must be
// read whole is a legitimate, explicit choice.
func TestFleetWideBodyCapOptOutRejected(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"0", "-1"} {
		_, err := parseResolve(t, `
defaults:
  http:
    max_body_bytes: `+value+`
targets:
  - name: inherits
    http:
      url: https://a.example
`)
		if err == nil {
			t.Fatalf("defaults.http.max_body_bytes: %s was accepted; one line would uncap the "+
				"body read for every target that does not set its own", value)
		}
		if !strings.Contains(err.Error(), "only allowed per target") {
			t.Errorf("error for defaults.http.max_body_bytes: %s = %q, want it to say the "+
				"opt-out is per-target only", value, err)
		}
	}
}

// TestFleetWideBodyCapOptOutRejectedEvenIfNoTargetInherits closes the loophole
// version of the same promise: the defaults block is invalid on its own terms,
// not merely when some target happens to inherit from it. Validating it only on
// inheritance would leave a config that passes CI today and uncaps the fleet the
// moment someone adds a target without an explicit cap — the change that
// introduces the risk would be the one line that looks harmless in review.
func TestFleetWideBodyCapOptOutRejectedEvenIfNoTargetInherits(t *testing.T) {
	t.Parallel()

	_, err := parseResolve(t, `
defaults:
  http:
    max_body_bytes: 0
targets:
  - name: explicit
    http:
      url: https://a.example
      max_body_bytes: 1048576
`)
	if err == nil {
		t.Fatal("defaults.http.max_body_bytes: 0 was accepted because every target overrode it; " +
			"the next target added without an explicit cap would silently inherit no cap")
	}
}

// TestPerTargetBodyCapOptOutStillAllowed is the other side: the promise is that
// the opt-out is *per target*, not that it is forbidden. Rejecting it outright
// would leave no way to probe an endpoint whose body must be read whole, and the
// operator's only recourse would be to drop the target from monitoring.
func TestPerTargetBodyCapOptOutStillAllowed(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
defaults:
  http:
    max_body_bytes: 1048576
targets:
  - name: uncapped
    http:
      url: https://a.example
      max_body_bytes: 0
`)
	if err != nil {
		t.Fatalf("a per-target opt-out was rejected: %v", err)
	}
	if got := cfg.Targets[0].HTTP.ResolvedMaxBodyBytes(); got != 0 {
		t.Errorf("resolved max_body_bytes = %d, want 0 (the explicit per-target opt-out must "+
			"survive the defaults merge)", got)
	}
}

// TestLoadRejectsUnreadableAndCorruptFiles covers the shapes a config file
// actually arrives in when something upstream went wrong: a path that is a
// directory (a bind mount that did not resolve to a file), a file the process
// cannot read (a secret mounted with the wrong ownership), and binary junk (a
// truncated or half-written file from a crashed deploy).
//
// Each must fail with an error that names the path, because this is the last
// thing an operator sees before the process exits: config.Load's error is
// printed to stderr and the exit code is non-zero. An error that says only
// "invalid config" leaves them guessing which of several mounted files is at
// fault, and a nil error here would start Sentinel with no targets at all —
// silently monitoring nothing while reporting itself healthy.
func TestLoadRejectsUnreadableAndCorruptFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	junk := filepath.Join(dir, "truncated.yaml")
	if err := os.WriteFile(junk, []byte{0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0x00}, 0o600); err != nil {
		t.Fatalf("writing the junk fixture: %v", err)
	}

	unreadable := filepath.Join(dir, "unreadable.yaml")
	if err := os.WriteFile(unreadable, []byte("targets: []\n"), 0o000); err != nil {
		t.Fatalf("writing the unreadable fixture: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"a directory instead of a file", dir},
		{"binary junk from a truncated write", junk},
		{"a file the process cannot read", unreadable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(tc.path)
			if err == nil {
				t.Fatalf("Load(%s) returned nil error and %d targets; Sentinel would start "+
					"monitoring nothing while reporting itself healthy", tc.name, len(cfg.Targets))
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error %q does not name the path %s; an operator cannot tell which "+
					"mounted file is at fault", err, tc.path)
			}
		})
	}
}

// TestLoadRejectsAnAliasExpandedDocument checks a YAML alias bomb is not
// expanded into memory. The config path is operator-supplied rather than
// attacker-supplied, so this is not a hostile-input defence — it is a guard
// against a config generator (a Helm template, an Ansible loop) producing a
// document whose anchors multiply out. Sentinel must reject it with a parse
// error rather than allocating the expansion during startup.
func TestLoadRejectsAnAliasExpandedDocument(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "aliases.yaml")
	doc := `a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: [*e,*e,*e,*e,*e,*e,*e,*e,*e]
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("an alias-expanded document was accepted; a generated config with multiplying " +
			"anchors would be expanded into memory at startup")
	}
}

// TestEmptyDocumentIsNotAValidConfig pins the empty-file case to the clear
// message rather than an opaque parse error, and — more importantly — to
// *failing*. An empty file is what a config generator produces when its input
// was empty, and a Sentinel that accepted it would come up green with zero
// targets: every dashboard would show no data, which reads as a Prometheus
// problem rather than as a monitoring process that was never given anything to
// watch.
func TestEmptyDocumentIsNotAValidConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"empty.yaml":    "",
		"comments.yaml": "# nothing here\n# really nothing\n",
		"blank.yaml":    "\n\n   \n",
		"nulldoc.yaml":  "---\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		cfg, lerr := Load(path)
		if lerr == nil {
			t.Errorf("Load(%s) accepted an empty document with %d targets; Sentinel would come "+
				"up green while monitoring nothing", name, len(cfg.Targets))
			continue
		}
		if !strings.Contains(lerr.Error(), "no targets defined") {
			t.Errorf("Load(%s) = %q, want the clear \"no targets defined\" message", name, lerr)
		}
	}
}
