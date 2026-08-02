# Sentinel Makefile
#
# All build/test/quality logic lives here so CI configs (Forgejo primary, GitHub
# optional) stay thin wrappers that only invoke `make` targets.

BINARY      := sentinel
CMD_PKG     := ./cmd/sentinel
BIN_DIR     := bin
DIST_DIR    := dist

MODULE      := bodsch.me/sentinel
VERSION_PKG := $(MODULE)/pkg/version

# Version metadata, overridable from the environment / CI.
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).Commit=$(COMMIT) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

# Static binaries: no cgo (see design decision Q26).
export CGO_ENABLED := 0

# Release target platforms.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

GO         := go
GOLANGCI   := golangci-lint

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the sentinel binary into bin/.
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)

.PHONY: test
test: ## Run the test suite with the race detector.
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile.
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: bench
bench: ## Run micro-benchmarks (no tests) with allocation stats.
	$(GO) test -run '^$$' -bench . -benchmem ./...

.PHONY: scaling
scaling: ## Run the scaling profile (goroutines/heap/scrape latency at N targets).
	SENTINEL_SCALING=1 $(GO) test -run TestScalingProfile -v -count=1 ./cmd/sentinel/

.PHONY: benchmark
benchmark: ## Run the Sentinel vs blackbox_exporter benchmark harness (see bench/).
	bench/run.sh

.PHONY: fmt
fmt: ## Format all Go source.
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint (must be installed).
	$(GOLANGCI) run ./...

.PHONY: tidy
tidy: ## Tidy and verify go.mod/go.sum.
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: ci
ci: fmt vet lint test build ## Full CI pipeline: fmt, vet, lint, test (race), build.

.PHONY: release
release: ## Cross-compile static release binaries into dist/.
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=$(DIST_DIR)/$(BINARY)-$$os-$$arch; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$out $(CMD_PKG) || exit 1; \
	done

.PHONY: clean
clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out
