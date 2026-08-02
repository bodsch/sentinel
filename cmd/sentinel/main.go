// Command sentinel is the Sentinel synthetic monitoring daemon.
//
// This is the 0.1 scaffold: flag parsing, logging setup and --version are wired.
// The probe runtime (config loading, scheduler, store, metrics/server) is added
// in subsequent steps; until then the run and --validate paths report that they
// are not yet implemented rather than pretending to work.
package main

import (
	"flag"
	"fmt"
	"os"

	"bodsch.me/sentinel/internal/config"
	"bodsch.me/sentinel/internal/logging"
	"bodsch.me/sentinel/pkg/version"
)

// exit codes
const (
	exitOK    = 0
	exitUsage = 2
	exitError = 1
)

// options holds the parsed command-line options.
type options struct {
	configPath  string
	validate    bool
	showVersion bool
	logLevel    string
	logFormat   string
	listen      string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses arguments and dispatches. It returns a process exit code. Splitting
// this out of main keeps it testable.
func run(args []string, stdout, stderr *os.File) int {
	cfg, code, done := parseFlags(args, stderr)
	if done {
		return code
	}

	if cfg.showVersion {
		fmt.Fprintln(stdout, version.Get().String())
		return exitOK
	}

	level, err := logging.ParseLevel(cfg.logLevel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	format, err := logging.ParseFormat(cfg.logFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	logger := logging.New(stderr, logging.Options{Level: level, Format: format})

	if cfg.configPath == "" {
		if p := os.Getenv("SENTINEL_CONFIG"); p != "" {
			cfg.configPath = p
		}
	}
	if cfg.configPath == "" {
		fmt.Fprintln(stderr, "sentinel: no config file given (use --config or SENTINEL_CONFIG)")
		return exitUsage
	}

	// Load and validate the configuration. This is fail-fast: an invalid config
	// stops the process rather than starting with a partial configuration.
	loaded, err := config.Load(cfg.configPath)
	if err != nil {
		// --validate is a CI/GitOps dry-run: report every problem and exit
		// non-zero without starting anything. A normal start fails the same way.
		fmt.Fprintln(stderr, err)
		return exitError
	}

	if cfg.validate {
		fmt.Fprintf(stdout, "config OK: %d target(s) in %s\n", len(loaded.Targets), cfg.configPath)
		return exitOK
	}

	logger.Info("sentinel starting",
		"version", version.Version,
		"commit", version.Commit,
		"config", cfg.configPath,
		"targets", len(loaded.Targets),
		"listen", cfg.listen,
	)

	// TODO(0.1): wire the scheduler, store and the metrics/health server around
	// the loaded configuration. Until then, fail loudly instead of silently
	// doing nothing.
	fmt.Fprintln(stderr, "sentinel: probe runtime is not implemented yet")
	return exitError
}

// parseFlags parses args into a config. The done flag is true when the process
// should exit immediately with the returned code (e.g. -h or a parse error).
func parseFlags(args []string, stderr *os.File) (cfg options, code int, done bool) {
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.configPath, "config", "", "path to the YAML config file (env: SENTINEL_CONFIG)")
	fs.BoolVar(&cfg.validate, "validate", false, "load and validate the config, then exit (no probes started)")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version information and exit")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&cfg.logFormat, "log-format", "json", "log format: json, text")
	fs.StringVar(&cfg.listen, "listen", ":8080", "HTTP listen address for /metrics, /healthz, /readyz")

	if err := fs.Parse(args); err != nil {
		// flag already printed the error / usage.
		return cfg, exitUsage, true
	}
	return cfg, exitOK, false
}
