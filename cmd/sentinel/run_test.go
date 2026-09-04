package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI invokes run() with real *os.File handles for stdout/stderr (its actual
// signature) and returns the exit code plus what each stream received.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()

	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("creating the stdout capture: %v", err)
	}
	errf, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("creating the stderr capture: %v", err)
	}

	code = run(args, out, errf)

	_ = out.Close()
	_ = errf.Close()
	ob, _ := os.ReadFile(out.Name())
	eb, _ := os.ReadFile(errf.Name())
	return code, string(ob), string(eb)
}

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentinel.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the config fixture: %v", err)
	}
	return path
}

const validConfig = `
targets:
  - name: example
    interval: 30s
    http:
      url: https://example.invalid
`

// TestRunRefusesToStartOnAnInvalidConfig is the fail-fast promise
// configuration.md makes: "On a normal start an invalid config is fail-fast —
// Sentinel refuses to start."
//
// It is asserted through run() rather than through config.Validate because the
// promise is about the *process*, and the two can disagree: validation could
// return an error that run() logs and then ignores, leaving Sentinel up with a
// partial target set. That failure is silent in the worst way — the targets that
// parsed keep reporting, so dashboards look populated, while the ones that did
// not are simply absent and nobody is alerted about the gap. A non-zero exit
// makes the deploy fail instead, which is the whole point of fail-fast.
func TestRunRefusesToStartOnAnInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "unknown field",
			yaml:    "targets:\n  - name: x\n    http:\n      urll: https://a.example\n",
			wantSub: "field urll not found",
		},
		{
			name:    "no targets",
			yaml:    "targets: []\n",
			wantSub: "no targets defined",
		},
		{
			name:    "credentials in the URL",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://user:pw@a.example\n",
			wantSub: "must not embed credentials",
		},
		{
			name:    "fleet-wide body cap opt-out",
			yaml:    "defaults:\n  http:\n    max_body_bytes: 0\ntargets:\n  - name: x\n    http:\n      url: https://a.example\n",
			wantSub: "only allowed per target",
		},
		{
			name:    "no protocol block",
			yaml:    "targets:\n  - name: x\n",
			wantSub: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, _, stderr := runCLI(t, "--config", writeConfig(t, tc.yaml))
			if code == exitOK {
				t.Fatalf("run exited %d (OK) on an invalid config; the daemon would start with "+
					"a partial target set and the missing targets would be silently unmonitored", code)
			}
			if tc.wantSub != "" && !strings.Contains(stderr, tc.wantSub) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.wantSub)
			}
		})
	}
}

// TestRunValidateIsADryRun covers the --validate contract configuration.md
// describes as the CI/GitOps check: report every problem and exit non-zero
// without starting anything, and exit zero on a good config.
//
// If --validate ever exited zero on a broken config, a GitOps pipeline would
// merge a config that then crash-loops the daemon in production — the check
// would be worse than absent, because someone is relying on it.
func TestRunValidateIsADryRun(t *testing.T) {
	t.Parallel()

	t.Run("good config exits zero and reports the target count", func(t *testing.T) {
		t.Parallel()
		code, stdout, stderr := runCLI(t, "--validate", "--config", writeConfig(t, validConfig))
		if code != exitOK {
			t.Fatalf("--validate on a valid config exited %d, want %d (stderr: %q)", code, exitOK, stderr)
		}
		if !strings.Contains(stdout, "config OK") || !strings.Contains(stdout, "1 target") {
			t.Errorf("stdout = %q, want it to confirm 1 target", stdout)
		}
	})

	t.Run("broken config exits non-zero", func(t *testing.T) {
		t.Parallel()
		bad := "targets:\n  - name: x\n    http:\n      url: ftp://a.example\n"
		code, stdout, stderr := runCLI(t, "--validate", "--config", writeConfig(t, bad))
		if code == exitOK {
			t.Fatalf("--validate exited %d (OK) on a config with an unsupported scheme; a GitOps "+
				"pipeline would merge a config that crash-loops the daemon", code)
		}
		if strings.Contains(stdout, "config OK") {
			t.Errorf("stdout claimed the config was OK: %q", stdout)
		}
		if !strings.Contains(stderr, "scheme must be http or https") {
			t.Errorf("stderr = %q, want the scheme error", stderr)
		}
	})
}

// TestRunReportsEveryProblemAtOnce is the second half of the --validate
// contract: "report every problem". Stopping at the first error turns fixing a
// config into one CI round-trip per mistake, which is how people end up
// skipping the check entirely.
func TestRunReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()

	yaml := `
targets:
  - name: a
    http:
      url: ftp://a.example
  - name: b
    http:
      url: https://b.example
      method: FETCH
  - name: c
    tcp:
      address: "b.example:notaport"
`
	code, _, stderr := runCLI(t, "--config", writeConfig(t, yaml))
	if code == exitOK {
		t.Fatalf("run exited OK on a config with three distinct errors")
	}

	for _, want := range []string{"scheme must be http or https", "http.method must be one of", "must be a number in 1-65535"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not mention %q; only the first problem was reported, so "+
				"fixing this config takes one CI round-trip per mistake:\n%s", want, stderr)
		}
	}
}

// TestRunRejectsBadLoggingFlags pins the flag guards to exit code 2 (usage), not
// 1 (error). An orchestrator distinguishes the two: a usage error means the unit
// file or Helm values are wrong and restarting will never help, while an error
// exit can be transient. Collapsing them makes a permanently broken deployment
// look like a flapping one, and it will restart forever.
func TestRunRejectsBadLoggingFlags(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfig(t, validConfig)

	tests := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"unknown log level", []string{"--log-level", "verbose", "--config", cfgPath}, "unknown level"},
		{"unknown log format", []string{"--log-format", "logfmt", "--config", cfgPath}, "unknown format"},
		{"unknown flag", []string{"--not-a-flag"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, _, stderr := runCLI(t, tc.args...)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d (usage); an orchestrator treats an error exit "+
					"as possibly transient and would restart forever", code, exitUsage)
			}
			if tc.wantSub != "" && !strings.Contains(stderr, tc.wantSub) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.wantSub)
			}
		})
	}
}

// TestRunWithoutAConfigPathIsAUsageError covers the case where neither --config
// nor SENTINEL_CONFIG is set. Defaulting to some conventional path instead would
// let a deployment that lost its config-path setting start against whatever
// happened to be at that path — or come up green with nothing to watch.
//
// SENTINEL_CONFIG is set with t.Setenv, so this test cannot run in parallel.
func TestRunWithoutAConfigPathIsAUsageError(t *testing.T) {
	t.Setenv("SENTINEL_CONFIG", "")

	code, _, stderr := runCLI(t)
	if code != exitUsage {
		t.Errorf("exit code with no config path = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(stderr, "no config file given") {
		t.Errorf("stderr = %q, want it to name --config and SENTINEL_CONFIG", stderr)
	}
}

// TestRunHonoursSentinelConfigEnv is the documented fallback: SENTINEL_CONFIG
// supplies the path when --config is absent. Container deployments set it
// instead of editing the command line, so a regression here breaks every such
// deployment while leaving the flag-based ones working — the kind of asymmetry
// that survives a whole release.
func TestRunHonoursSentinelConfigEnv(t *testing.T) {
	t.Setenv("SENTINEL_CONFIG", writeConfig(t, validConfig))

	code, stdout, stderr := runCLI(t, "--validate")
	if code != exitOK {
		t.Fatalf("--validate with SENTINEL_CONFIG set exited %d, want %d (stderr: %q)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "config OK") {
		t.Errorf("stdout = %q, want the config to be accepted from the environment", stdout)
	}
}

// TestRunExplicitFlagBeatsEnv pins the precedence: --config wins over
// SENTINEL_CONFIG. If the environment won instead, an operator debugging on a
// host with a stale exported variable would silently validate and run a
// different file than the one they passed on the command line, and every
// conclusion they drew from it would be about the wrong config.
func TestRunExplicitFlagBeatsEnv(t *testing.T) {
	broken := writeConfig(t, "targets: []\n")
	t.Setenv("SENTINEL_CONFIG", broken)

	code, stdout, stderr := runCLI(t, "--validate", "--config", writeConfig(t, validConfig))
	if code != exitOK {
		t.Fatalf("--config was overridden by SENTINEL_CONFIG: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "1 target") {
		t.Errorf("stdout = %q, want the flag's config (1 target), not the environment's", stdout)
	}
}

// TestRunVersionExitsZero covers the --version path: it must print to stdout and
// exit zero without needing a config. Container image smoke tests and release
// pipelines shell out to it, so a version flag that demanded a config (or wrote
// to stderr) would fail the build for a reason unrelated to the build.
func TestRunVersionExitsZero(t *testing.T) {
	t.Setenv("SENTINEL_CONFIG", "")

	code, stdout, stderr := runCLI(t, "--version")
	if code != exitOK {
		t.Fatalf("--version exited %d, want %d (stderr: %q)", code, exitOK, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("--version wrote nothing to stdout")
	}
	if strings.Contains(stdout, "no config file given") {
		t.Error("--version demanded a config file")
	}
}

// TestRunRejectsAnUnbuildableProber covers the gap between "the config is valid"
// and "a prober can be built from it": a ca_file that validates as a path but
// cannot be read. Validation deliberately does not touch the filesystem for
// target reachability, but the CA bundle and the client key pair are read at
// startup, and buildProber is where that fails.
//
// Exiting non-zero is what makes a missing or wrongly-mounted secret a deploy
// failure. Starting anyway would give a target that probes with the wrong trust
// store — reporting a certificate failure that is Sentinel's own
// misconfiguration, sending someone to debug a healthy server.
func TestRunRejectsAnUnbuildableProber(t *testing.T) {
	t.Parallel()

	missingCA := filepath.Join(t.TempDir(), "not-mounted-ca.pem")
	yaml := "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        ca_file: " + missingCA + "\n"

	code, _, stderr := runCLI(t, "--config", writeConfig(t, yaml))
	if code == exitOK {
		t.Fatalf("run exited OK with an unreadable ca_file; the target would probe against the "+
			"wrong trust store and report a certificate failure that is Sentinel's own "+
			"misconfiguration (stderr: %q)", stderr)
	}
}
