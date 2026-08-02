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

	// Every target must have exactly one resolved protocol block after Load.
	for _, tg := range cfg.Targets {
		switch {
		case tg.HTTP != nil && tg.DNS != nil:
			t.Errorf("target %q has both HTTP and DNS blocks", tg.Name)
		case tg.HTTP != nil:
			switch tg.HTTP.Method {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
				// ok
			default:
				t.Errorf("target %q resolved to unexpected method %q", tg.Name, tg.HTTP.Method)
			}
		case tg.DNS != nil:
			if _, ok := AllowedDNSTypes[tg.DNS.Type]; !ok {
				t.Errorf("target %q resolved to unexpected DNS type %q", tg.Name, tg.DNS.Type)
			}
		default:
			t.Errorf("target %q has no protocol block", tg.Name)
		}
	}
}
