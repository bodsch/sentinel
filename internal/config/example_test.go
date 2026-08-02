package config

import (
	"path/filepath"
	"testing"
)

// TestExampleConfigIsValid guards the shipped example configuration: if a change
// to the schema or validator ever makes config.example.yaml invalid, this test
// fails, keeping the example in sync with the code.
func TestExampleConfigIsValid(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("example config failed validation: %v", err)
	}

	if len(cfg.Targets) == 0 {
		t.Fatal("example config has no targets")
	}

	// Every target must have a resolved HTTP block after Load.
	for _, tg := range cfg.Targets {
		if tg.HTTP == nil {
			t.Errorf("target %q has no resolved HTTP block", tg.Name)
			continue
		}
		if tg.HTTP.Method != "GET" && tg.HTTP.Method != "HEAD" {
			t.Errorf("target %q resolved to unexpected method %q", tg.Name, tg.HTTP.Method)
		}
	}
}
