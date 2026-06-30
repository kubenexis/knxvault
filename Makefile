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
GO_TOOLCHAIN    ?= go1.25.11
GOLANGCI_LINT   := $(firstword $(shell command -v golangci-lint 2>/dev/null) $(GOPATH_BIN)/golangci-lint)
GOSEC           := $(firstword $(shell command -v gosec 2>/dev/null) $(GOPATH_BIN)/gosec)
TRIVY           := $(firstword $(shell command -v trivy 2>/dev/null) $(LOCAL_BIN)/trivy)
DOCKER          := $(firstword $(shell command -v docker 2>/dev/null))
IMAGE           ?= knxvault:0.1.0-dev
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

# -----------------------------------------------------------------------------
# Project artifacts
# -----------------------------------------------------------------------------
PROJECT         ?= knxvault
BINARY          ?= bin/knxvault
MAIN_PKG        ?= ./cmd/knxvault
SBOM_FILE       ?= sbom.json
TRIVY_CACHE_DIR ?= $(HOME)/.cache/trivy
LDFLAGS         ?= -s -w
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
all: ## Run fmt, vet, lint, gosec, licenses, scan, test, test-integration, build, and sbom
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory vet
	$(MAKE) --no-print-directory lint
	$(MAKE) --no-print-directory gosec
	$(MAKE) --no-print-directory licenses
	$(MAKE) --no-print-directory scan
	$(MAKE) --no-print-directory test
	$(MAKE) --no-print-directory test-integration
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory sbom
	@printf "$(COLOR_GREEN)All pipeline stages passed.$(COLOR_RESET)\n"

# =============================================================================
# Go quality
# =============================================================================

.PHONY: fmt vet lint gosec licenses test test-integration build sbom scan tidy install-tools docker-build

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
	$(call require_cmd,golangci-lint)
	$(GOLANGCI_LINT) run ./...

gosec: ## Run gosec security scanner (W11-02)
	$(call log,Running gosec)
	$(call require_cmd,gosec)
	$(GOSEC) -quiet -conf .gosec.json -exclude-generated -severity high ./...

licenses: ## Enforce permissive dependency licenses (LLD §1.5)
	$(call log,Checking dependency licenses)
	$(call require_cmd,bash)
	@bash scripts/check-licenses.sh

test: ## Run unit tests
	$(call log,Running go test)
	$(call require_cmd,go)
	$(GO) test $$(go list ./... | grep -v '/test/integration') -count=1

test-integration: ## Run integration tests (API always; Postgres if compose available)
	$(call log,Running integration tests)
	$(call require_cmd,go)
	$(GO) test ./test/integration/... -count=1
	@if [ -n "$(DOCKER)" ] && [ -f docker-compose.test.yml ]; then \
		$(MAKE) --no-print-directory test-integration-postgres; \
	fi

test-integration-postgres: ## Run Postgres integration tests via docker compose
	$(call log,Starting test PostgreSQL)
	$(DOCKER) compose -f docker-compose.test.yml up -d --wait
	@KNXVAULT_TEST_DATABASE_URL='postgres://knxvault:knxvault@localhost:54329/knxvault?sslmode=disable' \
		$(GO) test ./test/integration/... -run TestIntegrationPostgres -count=1; \
		status=$$?; \
		$(DOCKER) compose -f docker-compose.test.yml down; \
		exit $$status

docker-build: ## Build container image ($(IMAGE))
	$(call log,Building Docker image $(IMAGE))
	$(call require_cmd,docker)
	$(DOCKER) build -t $(IMAGE) .

build: ## Build statically linked release binary to bin/knxvault
	$(call log,Building static binary $(BINARY))
	$(call require_cmd,go)
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(MAIN_PKG)
	@file $(BINARY) | grep -q 'statically linked'
	@(ldd $(BINARY) 2>&1 || true) | grep -q 'not a dynamic executable'

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

install-tools: ## Install golangci-lint v2 and gosec (Go 1.25 toolchain)
	$(call log,Installing golangci-lint v2 and gosec)
	$(call require_cmd,go)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) install github.com/securego/gosec/v2/cmd/gosec@v2.22.11
	@printf "$(COLOR_GREEN)tools installed to $(GOPATH_BIN)$(COLOR_RESET)\n"

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
	@printf "  make test\n"