# =============================================================================
# KNXVault — Production GNU Makefile
# Go quality pipeline, SBOM generation, and security scanning.
# =============================================================================

SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.ONESHELL:
MAKEFLAGS     += --no-builtin-rules
.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Tooling
# -----------------------------------------------------------------------------
LOCAL_BIN       ?= $(HOME)/.local/bin
GOPATH_BIN      ?= $(HOME)/go/bin
export PATH     := $(GOPATH_BIN):$(LOCAL_BIN):$(PATH)
GO              := $(firstword $(shell command -v go 2>/dev/null))
GO_TOOLCHAIN    ?= go1.26.4
GOLANGCI_LINT   ?= $(GOPATH_BIN)/golangci-lint
GOSEC           ?= $(GOPATH_BIN)/gosec
TRIVY           := $(firstword $(shell command -v trivy 2>/dev/null) $(LOCAL_BIN)/trivy)
# Container CLI: prefer docker, fall back to nerdctl (air-gapped / containerd hosts).
DOCKER          := $(firstword $(shell command -v docker 2>/dev/null) $(shell command -v nerdctl 2>/dev/null))
VERSION         ?= 0.4.5
COMMIT          ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_ID        ?= $(shell date +%s)
IMAGE           ?= knxvault:$(VERSION)
OPERATOR_IMAGE  ?= knxvault-operator:$(VERSION)
# Only supported runtime: multi-stage → gcr.io/distroless/static-debian13:nonroot
DOCKERFILE      ?= Dockerfile
DOCKERFILE_OPERATOR ?= Dockerfile.operator
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

# -----------------------------------------------------------------------------
# Project artifacts
# -----------------------------------------------------------------------------
PROJECT         ?= knxvault
BINARY          ?= bin/knxvault
CLI_BINARY      ?= bin/knxvault-cli
CSI_BINARY      ?= bin/knxvault-csi
WEBHOOK_BINARY  ?= bin/knxvault-webhook
ESO_BINARY      ?= bin/knxvault-eso
OPERATOR_BINARY ?= bin/knxvault-operator
MAIN_PKG        ?= ./cmd/knxvault
CLI_PKG         ?= ./cmd/knxvault-cli
CSI_PKG         ?= ./cmd/knxvault-csi
WEBHOOK_PKG     ?= ./cmd/knxvault-webhook
ESO_PKG         ?= ./cmd/knxvault-eso
OPERATOR_PKG    ?= ./cmd/operator
COVERAGE_MIN    ?= 80
SBOM_FILE       ?= sbom.json
TRIVY_CACHE_DIR ?= $(HOME)/.cache/trivy
LDFLAGS         ?= -s -w \
	-X github.com/kubenexis/knxvault/internal/version.Version=$(VERSION) \
	-X github.com/kubenexis/knxvault/internal/version.Commit=$(COMMIT) \
	-X github.com/kubenexis/knxvault/internal/version.BuildID=$(BUILD_ID)
TRIVY_SEVERITY  ?= HIGH,CRITICAL

# -----------------------------------------------------------------------------
# Colorized output
# -----------------------------------------------------------------------------
ifeq ($(NO_COLOR),)
  ifneq ($(shell test -t 1 && echo 1),)
    COLOR_RESET  := \033[0m
    COLOR_BOLD   := \033[1m
    COLOR_DIM    := \033[2m
    COLOR_RED    := \033[31m
    COLOR_GREEN  := \033[32m
    COLOR_YELLOW := \033[33m
    COLOR_CYAN   := \033[36m
  endif
endif

define log
	@printf "$(COLOR_BOLD)==> $(1)$(COLOR_RESET)\n"
endef

define require_cmd
	@command -v $(1) >/dev/null 2>&1 || { \
		printf "$(COLOR_RED)error: $(1) not found$(COLOR_RESET)\n" >&2; \
		exit 1; \
	}
endef

# =============================================================================
# Primary pipeline
# =============================================================================

.PHONY: all
all: ## Run fmt, vet, lint, docs-lint, gosec, licenses, scan, test, test-integration, build, and sbom
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory vet
	$(MAKE) --no-print-directory lint
	$(MAKE) --no-print-directory docs-lint
	$(MAKE) --no-print-directory gosec
	$(MAKE) --no-print-directory licenses
	$(MAKE) --no-print-directory scan
	$(MAKE) --no-print-directory test
	$(MAKE) --no-print-directory test-integration
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory build-cli
	$(MAKE) --no-print-directory sbom
	@printf "$(COLOR_GREEN)All pipeline stages passed.$(COLOR_RESET)\n"

# =============================================================================
# Go quality
# =============================================================================

.PHONY: fmt vet lint docs-lint gosec semgrep licenses test test-integration test-coverage build build-cli build-csi build-webhook build-eso build-operator generate-clients test-clients check-client-drift sbom scan tidy install-tools docker-build docker-build-operator docker-build-all clean

fmt: ## Check Go formatting (gofmt)
	$(call log,Checking gofmt)
	$(call require_cmd,go)
	@files=$$(find . -name '*.go' -not -path './vendor/*'); \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then \
		printf "$(COLOR_RED)unformatted files:$(COLOR_RESET)\n$$unformatted\n" >&2; \
		exit 1; \
	fi

vet: ## Run go vet on all packages
	$(call log,Running go vet)
	$(call require_cmd,go)
	$(GO) vet ./...

lint: ## Run golangci-lint
	$(call log,Running golangci-lint)
	@test -x "$(GOLANGCI_LINT)" || { \
		printf "$(COLOR_RED)error: golangci-lint not found (expected at $(GOLANGCI_LINT))$(COLOR_RESET)\n" >&2; \
		printf "Run: make install-tools  # builds with GOTOOLCHAIN=$(GO_TOOLCHAIN)\n" >&2; \
		exit 1; \
	}
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GOLANGCI_LINT) run ./...

docs-lint: ## Fail bare `kv get` docs without redaction/--show-secrets context
	$(call log,Checking kv get documentation)
	$(call require_cmd,bash)
	@bash scripts/check-kv-get-docs.sh

gosec: ## Run gosec security scanner (W11-02)
	$(call log,Running gosec)
	@test -x "$(GOSEC)" || { \
		printf "$(COLOR_RED)error: gosec not found (expected at $(GOSEC))$(COLOR_RESET)\n" >&2; \
		printf "Run: make install-tools\n" >&2; \
		exit 1; \
	}
	$(GOSEC) -quiet -conf .gosec.json -exclude-generated -severity high ./...

semgrep: ## Run semgrep static analysis (W38-16)
	$(call log,Running semgrep)
	$(call require_cmd,semgrep)
	semgrep scan --config .semgrep/knxvault.yml --error .

licenses: ## Enforce permissive dependency licenses (LLD §1.5)
	$(call log,Checking dependency licenses)
	$(call require_cmd,bash)
	@bash scripts/check-licenses.sh

test: ## Run unit tests
	$(call log,Running go test)
	$(call require_cmd,go)
	$(GO) test $$(go list ./... | grep -v '/test/integration') -count=1

test-coverage: ## Coverage gate ≥COVERAGE_MIN% on pure operator/acme packages
	$(call log,Running coverage gate (min $(COVERAGE_MIN)% on pure logic packages))
	$(call require_cmd,go)
	@$(GO) test ./internal/operator/renew ./internal/operator/secretutil ./internal/operator/statusutil \
		./internal/operator/reconcileutil ./internal/operator/certlogic \
		./internal/acme \
		-count=1 -covermode=atomic -coverprofile=coverage-operator.out; \
	$(GO) test ./internal/operator/cmcompat ./internal/operator/apis/v1alpha1 -count=1 -cover 2>&1 | tail -6; \
	pct=$$($(GO) tool cover -func=coverage-operator.out | awk '/^total:/{gsub(/%/,"",$$3); print $$3}'); \
	echo "operator pure-logic coverage: $${pct}% (min $(COVERAGE_MIN)%)"; \
	awk -v p="$${pct}" -v m="$(COVERAGE_MIN)" 'BEGIN{ if ((p+0) < (m+0)) { print "coverage below gate" > "/dev/stderr"; exit 1 } }'; \
	$(GO) test ./internal/operator/controllers ./internal/operator/vaultiface -count=1 -cover 2>&1 | tail -8

test-integration: build build-cli ## Run integration tests (API + Raft + daemon e2e)
	$(call log,Running integration tests)
	$(call require_cmd,go)
	$(GO) test ./test/integration/... -count=1

# Lab host full E2E (SSH). Override: make lab-full-e2e LAB_HOST=192.168.137.131
LAB_HOST ?= 192.168.137.131
lab-full-e2e: ## Full lab E2E on LAB_HOST (core + vaultcompat + operator)
	$(call log,Lab full E2E on $(LAB_HOST))
	bash scripts/lab-full-e2e.sh $(LAB_HOST)

docker-build: ## Build distroless server image ($(IMAGE)) via docker or nerdctl
	$(call log,Building distroless Debian 13 image $(IMAGE) with $(DOCKER))
	@command -v $(notdir $(DOCKER)) >/dev/null 2>&1 || { \
		printf "$(COLOR_RED)error: neither docker nor nerdctl found$(COLOR_RESET)\n" >&2; \
		exit 1; \
	}
	$(DOCKER) build \
		-f $(DOCKERFILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_ID=$(BUILD_ID) \
		-t $(IMAGE) .

docker-build-operator: ## Build distroless operator image ($(OPERATOR_IMAGE))
	$(call log,Building distroless operator image $(OPERATOR_IMAGE) with $(DOCKER))
	@command -v $(notdir $(DOCKER)) >/dev/null 2>&1 || { \
		printf "$(COLOR_RED)error: neither docker nor nerdctl found$(COLOR_RESET)\n" >&2; \
		exit 1; \
	}
	$(DOCKER) build \
		-f $(DOCKERFILE_OPERATOR) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_ID=$(BUILD_ID) \
		-t $(OPERATOR_IMAGE) .

docker-build-all: docker-build docker-build-operator ## Build server + operator distroless images

build: ## Build statically linked release binary to bin/knxvault
	$(call log,Building static binary $(BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(MAIN_PKG)
	@file $(BINARY) | grep -q 'statically linked'
	@(ldd $(BINARY) 2>&1 || true) | grep -q 'not a dynamic executable'

build-cli: ## Build statically linked CLI binary to bin/knxvault-cli
	$(call log,Building CLI binary $(CLI_BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(CLI_BINARY) $(CLI_PKG)

build-csi: ## Build Secrets Store CSI provider binary
	$(call log,Building CSI provider $(CSI_BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(CSI_BINARY) $(CSI_PKG)

build-webhook: ## Build mutating admission webhook binary
	$(call log,Building webhook $(WEBHOOK_BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(WEBHOOK_BINARY) $(WEBHOOK_PKG)

build-eso: ## Build External Secrets Operator webhook adapter
	$(call log,Building ESO adapter $(ESO_BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(ESO_BINARY) $(ESO_PKG)

build-operator: ## Build knxvault-operator (cert-manager replacement CRDs)
	$(call log,Building operator $(OPERATOR_BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(OPERATOR_BINARY) $(OPERATOR_PKG)
	@file $(OPERATOR_BINARY) | grep -q 'statically linked' || file $(OPERATOR_BINARY)

generate-clients: ## Generate Python, TypeScript, Java, Rust SDKs from OpenAPI
	$(call log,Generating client SDKs)
	$(call require_cmd,bash)
	@bash scripts/generate-clients.sh

test-clients: ## Verify generated client SDK trees exist
	$(call log,Testing client SDK artifacts)
	$(call require_cmd,bash)
	@bash scripts/test-clients.sh

check-client-drift: ## Fail when OpenAPI changed without regenerating clients
	$(call log,Checking OpenAPI client drift)
	$(call require_cmd,bash)
	@bash scripts/check-client-drift.sh

sbom: ## Generate CycloneDX SBOM (modules + release binary)
	@test -f $(BINARY) || $(MAKE) --no-print-directory build
	$(call log,Generating SBOM $(SBOM_FILE))
	$(call require_cmd,trivy)
	$(TRIVY) fs --cache-dir $(TRIVY_CACHE_DIR) \
		--format cyclonedx --output $(SBOM_FILE) .
	$(TRIVY) rootfs --cache-dir $(TRIVY_CACHE_DIR) \
		--format cyclonedx --output sbom-binary.json $(BINARY)
	@test -s $(SBOM_FILE)

scan: ## Trivy vulnerability scan (repo + binary if present)
	$(call log,Running Trivy filesystem scan)
	$(call require_cmd,trivy)
	$(TRIVY) fs --cache-dir $(TRIVY_CACHE_DIR) \
		--ignorefile .trivyignore \
		--severity $(TRIVY_SEVERITY) --exit-code 1 --scanners vuln .
	@if [ -f $(BINARY) ]; then \
		$(TRIVY) rootfs --cache-dir $(TRIVY_CACHE_DIR) \
			--ignorefile .trivyignore \
			--severity $(TRIVY_SEVERITY) --exit-code 1 --scanners vuln $(BINARY); \
	fi

tidy: ## Run go mod tidy
	$(call log,Running go mod tidy)
	$(call require_cmd,go)
	$(GO) mod tidy

clean: ## Remove built binaries and generated artifacts
	$(call log,Cleaning build artifacts)
	@rm -rf bin
	@rm -f $(SBOM_FILE) sbom-binary.json coverage.out trivy-report.json trivy-results.sarif
	@printf "$(COLOR_GREEN)Clean complete.$(COLOR_RESET)\n"

install-tools: ## Install golangci-lint v2 and gosec (Go 1.26 toolchain)
	$(call log,Installing golangci-lint v2 and gosec)
	$(call require_cmd,go)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	@printf "$(COLOR_GREEN)tools installed to $(GOPATH_BIN) (built with $(GO_TOOLCHAIN))$(COLOR_RESET)\n"

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Show available targets and descriptions
	@printf "$(COLOR_BOLD)KNXVault — Available Targets$(COLOR_RESET)\n\n"
	@printf "$(COLOR_DIM)Usage: make <target>  |  default: make help$(COLOR_RESET)\n\n"
	@grep -hE '^[a-zA-Z][a-zA-Z0-9_.-]*:.*## ' $(MAKEFILE_LIST) \
		| sort -u \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  $(COLOR_GREEN)make %-18s$(COLOR_RESET) %s\n", $$1, $$2}'
	@printf "\n$(COLOR_BOLD)Variables$(COLOR_RESET)\n\n"
	@printf "  $(COLOR_CYAN)BINARY$(COLOR_RESET)          = $(BINARY)\n"
	@printf "  $(COLOR_CYAN)SBOM_FILE$(COLOR_RESET)       = $(SBOM_FILE)\n"
	@printf "  $(COLOR_CYAN)TRIVY_SEVERITY$(COLOR_RESET)  = $(TRIVY_SEVERITY)\n"
	@printf "  $(COLOR_CYAN)TRIVY_CACHE_DIR$(COLOR_RESET) = $(TRIVY_CACHE_DIR)\n"
	@printf "  $(COLOR_CYAN)GO_TOOLCHAIN$(COLOR_RESET)    = $(GO_TOOLCHAIN)\n"
	@printf "\n$(COLOR_BOLD)Examples$(COLOR_RESET)\n\n"
	@printf "  make all\n"
	@printf "  make build\n"
	@printf "  make clean\n"
	@printf "  make test\n"