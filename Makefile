# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0

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
GO_TOOLCHAIN    ?= go1.26.5
GOLANGCI_LINT   ?= $(GOPATH_BIN)/golangci-lint
GOSEC           ?= $(GOPATH_BIN)/gosec
TRIVY           := $(firstword $(shell command -v trivy 2>/dev/null) $(LOCAL_BIN)/trivy)
# Container CLI: first working backend (docker, rootless nerdctl, or rootful sudo nerdctl).
# Override: make container-build DOCKER='sudo nerdctl'
DOCKER ?= $(shell \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		command -v docker; \
	elif command -v nerdctl >/dev/null 2>&1 && nerdctl info >/dev/null 2>&1; then \
		command -v nerdctl; \
	elif command -v nerdctl >/dev/null 2>&1 && sudo -n nerdctl info >/dev/null 2>&1; then \
		echo "sudo nerdctl"; \
	elif command -v nerdctl >/dev/null 2>&1 && sudo nerdctl info >/dev/null 2>&1; then \
		echo "sudo nerdctl"; \
	else \
		echo ""; \
	fi)
VERSION         ?= 0.5.1
COMMIT          ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_ID        ?= $(shell date +%s)
# GHCR image names: ghcr.io/<org>/<repository>:<tag>
# Override IMAGE_ORG for forks; override IMAGE/OPERATOR_IMAGE for full custom refs.
IMAGE_REGISTRY  ?= ghcr.io
IMAGE_ORG       ?= kubenexis
IMAGE_NAME      ?= knxvault
OPERATOR_IMAGE_NAME ?= knxvault-operator
IMAGE_REPOSITORY          ?= $(IMAGE_REGISTRY)/$(IMAGE_ORG)/$(IMAGE_NAME)
OPERATOR_IMAGE_REPOSITORY ?= $(IMAGE_REGISTRY)/$(IMAGE_ORG)/$(OPERATOR_IMAGE_NAME)
# Image/tarball identity: version + short commit (e.g. 0.5.1-a1b2c3d).
IMAGE_TAG       ?= $(VERSION)-$(COMMIT)
IMAGE           ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
OPERATOR_IMAGE  ?= $(OPERATOR_IMAGE_REPOSITORY):$(IMAGE_TAG)
# Floating tags without commit (local manifests / "latest semver"); always also tagged after build.
IMAGE_VERSION   ?= $(IMAGE_REPOSITORY):$(VERSION)
OPERATOR_IMAGE_VERSION ?= $(OPERATOR_IMAGE_REPOSITORY):$(VERSION)
# All build artifacts live under BUILD_DIR (binaries, image tarballs, SBOM, coverage).
BUILD_DIR       ?= build
BIN_DIR         ?= $(BUILD_DIR)/bin
CLI_RELEASE_DIR ?= $(BUILD_DIR)/release/cli
IMAGE_EXPORT_DIR ?= $(BUILD_DIR)/images
IMAGE_TAR       ?= $(IMAGE_EXPORT_DIR)/knxvault-$(IMAGE_TAG).tar
OPERATOR_TAR    ?= $(IMAGE_EXPORT_DIR)/knxvault-operator-$(IMAGE_TAG).tar
IMAGE_BUILD_INFO ?= $(IMAGE_EXPORT_DIR)/build-info-$(IMAGE_TAG).txt
# Only supported runtime: multi-stage → gcr.io/distroless/static-debian13:nonroot
DOCKERFILE      ?= Dockerfile
DOCKERFILE_OPERATOR ?= Dockerfile.operator
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

# -----------------------------------------------------------------------------
# Project artifacts
# -----------------------------------------------------------------------------
PROJECT         ?= knxvault
BINARY          ?= $(BIN_DIR)/knxvault
CLI_BINARY      ?= $(BIN_DIR)/knxvault-cli
CSI_BINARY      ?= $(BIN_DIR)/knxvault-csi
WEBHOOK_BINARY  ?= $(BIN_DIR)/knxvault-webhook
ESO_BINARY      ?= $(BIN_DIR)/knxvault-eso
OPERATOR_BINARY ?= $(BIN_DIR)/knxvault-operator
MAIN_PKG        ?= ./cmd/knxvault
CLI_PKG         ?= ./cmd/knxvault-cli
CSI_PKG         ?= ./cmd/knxvault-csi
WEBHOOK_PKG     ?= ./cmd/knxvault-webhook
ESO_PKG         ?= ./cmd/knxvault-eso
OPERATOR_PKG    ?= ./cmd/operator
COVERAGE_MIN    ?= 80
SBOM_FILE       ?= $(BUILD_DIR)/sbom.json
SBOM_BINARY_FILE ?= $(BUILD_DIR)/sbom-binary.json
COVERAGE_OPERATOR_OUT ?= $(BUILD_DIR)/coverage-operator.out
COVERAGE_ACME_OUT     ?= $(BUILD_DIR)/coverage-acme.out
TRIVY_CACHE_DIR ?= $(HOME)/.cache/trivy
TRIVY_REPORT    ?= $(BUILD_DIR)/trivy-report.json
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

.PHONY: all quality package-all
# Pre-merge quality gate (no container image build, no integration suite).
quality: ## Pre-merge gate: fmt vet lint docs-lint dtp-surface gosec licenses license-headers-check scan test test-coverage
	@$(MAKE) --no-print-directory fmt
	@$(MAKE) --no-print-directory vet
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory docs-lint
	@$(MAKE) --no-print-directory dtp-surface
	@$(MAKE) --no-print-directory gosec
	@$(MAKE) --no-print-directory licenses
	@$(MAKE) --no-print-directory license-headers-check
	@$(MAKE) --no-print-directory scan
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-coverage
	@printf "$(COLOR_GREEN)Quality gate passed.$(COLOR_RESET)\n"

# Full local pipeline including integration tests, binaries, and SBOM.
# Does NOT build container images or multi-platform CLI packages — use package-all.
all: ## quality + test-integration + build + build-cli + sbom
	@$(MAKE) --no-print-directory quality
	@$(MAKE) --no-print-directory test-integration
	@$(MAKE) --no-print-directory build
	@$(MAKE) --no-print-directory build-cli
	@$(MAKE) --no-print-directory sbom
	@printf "$(COLOR_GREEN)All pipeline stages passed.$(COLOR_RESET)\n"

# CI packaging parity: both container images + multi-platform knxvault-cli archives.
# Requires a working container CLI (docker / nerdctl). Does not push or export air-gap tarballs.
package-all: ## container-build-all + package-cli-release (CI packaging parity)
	$(call log,package-all: server + operator images and multi-platform knxvault-cli packages)
	@$(MAKE) --no-print-directory container-build-all
	@$(MAKE) --no-print-directory package-cli-release
	@printf "$(COLOR_GREEN)package-all complete.$(COLOR_RESET)\n"
	@printf "  Images:  $(IMAGE)  $(OPERATOR_IMAGE)\n"
	@printf "  CLI:     $(CLI_RELEASE_DIR)/\n"
	@printf "  Optional air-gap: make container-export-all\n"

# =============================================================================
# Go quality
# =============================================================================

.PHONY: all quality package-all fmt vet lint docs-lint dtp-surface gosec semgrep licenses license-headers license-headers-check test test-integration test-coverage build build-cli package-cli-release build-csi build-webhook build-eso build-operator generate-clients test-clients check-client-drift sbom scan tidy install-tools container-build k8s-operator-build container-build-all container-export k8s-operator-export container-export-all docker-build docker-build-operator docker-build-all clean

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

dtp-surface: ## W90-14: base/production kustomize must not include CSI/ESO/webhook/ACME
	$(call log,Checking DTP base deploy surface)
	$(call require_cmd,bash)
	@bash scripts/check-dtp-surface.sh

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

license-headers: ## Add missing SPDX license headers (Apache-2.0 code / CC-BY-4.0 docs)
	$(call log,Ensuring SPDX license headers)
	$(call require_cmd,bash)
	@bash scripts/ensure-license-headers.sh

license-headers-check: ## Fail if SPDX license headers are missing (CNCF Charter §11)
	$(call log,Checking SPDX license headers)
	$(call require_cmd,bash)
	@bash scripts/ensure-license-headers.sh --check

test: ## Run unit tests
	$(call log,Running go test)
	$(call require_cmd,go)
	$(GO) test $$(go list ./... | grep -v '/test/integration') -count=1

# ACME package includes network/Issue paths; gate pure logic at COVERAGE_MIN and acme at COVERAGE_ACME_MIN.
COVERAGE_ACME_MIN ?= 70
test-coverage: ## Coverage gate ≥COVERAGE_MIN% operator pure-logic; ≥COVERAGE_ACME_MIN% acme
	$(call log,Running coverage gate - operator min $(COVERAGE_MIN) pct acme min $(COVERAGE_ACME_MIN) pct)
	$(call require_cmd,go)
	@mkdir -p $(BUILD_DIR)
	@$(GO) test ./internal/operator/renew ./internal/operator/secretutil ./internal/operator/statusutil \
		./internal/operator/reconcileutil ./internal/operator/certlogic \
		-count=1 -covermode=atomic -coverprofile=$(COVERAGE_OPERATOR_OUT); \
	$(GO) test ./internal/operator/cmcompat ./internal/operator/apis/v1alpha1 -count=1 -cover 2>&1 | tail -6; \
	pct=$$($(GO) tool cover -func=$(COVERAGE_OPERATOR_OUT) | awk '/^total:/{gsub(/%/,"",$$3); print $$3}'); \
	echo "operator pure-logic coverage: $${pct}% (min $(COVERAGE_MIN)%)"; \
	awk -v p="$${pct}" -v m="$(COVERAGE_MIN)" 'BEGIN{ if ((p+0) < (m+0)) { print "coverage below gate" > "/dev/stderr"; exit 1 } }'; \
	$(GO) test ./internal/acme ./internal/acme/filestore ./internal/acme/vaultstore \
		-count=1 -covermode=atomic -coverprofile=$(COVERAGE_ACME_OUT); \
	apct=$$($(GO) tool cover -func=$(COVERAGE_ACME_OUT) | awk '/^total:/{gsub(/%/,"",$$3); print $$3}'); \
	echo "acme package coverage: $${apct}% (min $(COVERAGE_ACME_MIN)%)"; \
	awk -v p="$${apct}" -v m="$(COVERAGE_ACME_MIN)" 'BEGIN{ if ((p+0) < (m+0)) { print "acme coverage below gate" > "/dev/stderr"; exit 1 } }'; \
	$(GO) test ./internal/operator/controllers ./internal/operator/vaultiface -count=1 -cover 2>&1 | tail -8

test-integration: build build-cli ## Run integration tests (API + Raft + daemon e2e)
	$(call log,Running integration tests)
	$(call require_cmd,go)
	# 5m covers multi-node Raft under load + e2e binary rebuild; -count=1 disables cache.
	$(GO) test ./test/integration/... -count=1 -timeout 5m -p 1

# Lab host full E2E (SSH). Override: make lab-full-e2e LAB_HOST=192.168.137.131
LAB_HOST ?= 192.168.137.131
lab-full-e2e: ## Full lab E2E on LAB_HOST (core + vaultcompat + operator)
	$(call log,Lab full E2E on $(LAB_HOST))
	bash scripts/lab-full-e2e.sh $(LAB_HOST)

# Fail fast if no working container engine (rootless nerdctl often needs setup or sudo).
define require_container_cli
	@if [ -z "$(strip $(DOCKER))" ]; then \
		printf "$(COLOR_RED)error: no working container CLI (docker/nerdctl)$(COLOR_RESET)\n" >&2; \
		printf "  tried: docker info, nerdctl info, sudo nerdctl info\n" >&2; \
		printf "  fix one of:\n" >&2; \
		printf "    - start Docker daemon, or\n" >&2; \
		printf "    - rootless: containerd-rootless-setuptool.sh install, or\n" >&2; \
		printf "    - rootful containerd: make container-build DOCKER='sudo nerdctl'\n" >&2; \
		exit 1; \
	fi
endef

# Ensure a just-built image is visible to $(DOCKER).
define ensure_image
	@ref="$(1)"; \
	if $(DOCKER) image inspect "$$ref" >/dev/null 2>&1; then \
		: ; \
	else \
		printf "$(COLOR_RED)error: image $$ref not found after build$(COLOR_RESET)\n" >&2; \
		printf "  DOCKER=$(DOCKER)\n" >&2; \
		printf "  Looking for tag $(IMAGE_TAG). Images matching 'knxvault|$(IMAGE_ORG)':\n" >&2; \
		$(DOCKER) images 2>/dev/null | grep -E 'knxvault|$(IMAGE_ORG)|REPOSITORY' | head -20 >&2 || true; \
		printf "  Hint: rebuild with: make container-build DOCKER='$(DOCKER)'\n" >&2; \
		exit 1; \
	fi
endef

define save_image
	@mkdir -p $(IMAGE_EXPORT_DIR)
	$(call ensure_image,$(1))
	@$(DOCKER) save -o $(2) "$(1)"; \
	test -s $(2); \
	ls -lh $(2); \
	printf "$(COLOR_GREEN)Load on target: $(DOCKER) load -i $(2)$(COLOR_RESET)\n"
endef

container-build: ## Build distroless server image ($(IMAGE)); also tags $(IMAGE_VERSION)
	$(call log,Building distroless Debian 13 image $(IMAGE) with $(DOCKER))
	$(call require_container_cli)
	@$(DOCKER) build \
		-f $(DOCKERFILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_ID=$(BUILD_ID) \
		-t $(IMAGE) \
		-t $(IMAGE_VERSION) \
		.
	$(call ensure_image,$(IMAGE))
	@printf "$(COLOR_GREEN)Built $(IMAGE) (alias $(IMAGE_VERSION))$(COLOR_RESET)\n"

k8s-operator-build: ## Build distroless operator image ($(OPERATOR_IMAGE)); also tags $(OPERATOR_IMAGE_VERSION)
	$(call log,Building distroless operator image $(OPERATOR_IMAGE) with $(DOCKER))
	$(call require_container_cli)
	@$(DOCKER) build \
		-f $(DOCKERFILE_OPERATOR) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_ID=$(BUILD_ID) \
		-t $(OPERATOR_IMAGE) \
		-t $(OPERATOR_IMAGE_VERSION) \
		.
	$(call ensure_image,$(OPERATOR_IMAGE))
	@printf "$(COLOR_GREEN)Built $(OPERATOR_IMAGE) (alias $(OPERATOR_IMAGE_VERSION))$(COLOR_RESET)\n"

container-build-all: container-build k8s-operator-build ## Build server + operator distroless images

# Export always rebuilds so `make clean container-export-all` works and tags match this COMMIT.
container-export: container-build ## Build (if needed) and export server image → $(IMAGE_TAR)
	$(call log,Exporting $(IMAGE) → $(IMAGE_TAR))
	$(call require_container_cli)
	$(call save_image,$(IMAGE),$(IMAGE_TAR))

k8s-operator-export: k8s-operator-build ## Build (if needed) and export operator image → $(OPERATOR_TAR)
	$(call log,Exporting $(OPERATOR_IMAGE) → $(OPERATOR_TAR))
	$(call require_container_cli)
	$(call save_image,$(OPERATOR_IMAGE),$(OPERATOR_TAR))

# Write build-info sidecar next to tarballs for air-gap inventory.
define write_image_build_info
	@mkdir -p $(IMAGE_EXPORT_DIR)
	@printf '%s\n' \
		"version=$(VERSION)" \
		"commit=$(COMMIT)" \
		"build_id=$(BUILD_ID)" \
		"image_tag=$(IMAGE_TAG)" \
		"image_registry=$(IMAGE_REGISTRY)" \
		"image_org=$(IMAGE_ORG)" \
		"server_repository=$(IMAGE_REPOSITORY)" \
		"operator_repository=$(OPERATOR_IMAGE_REPOSITORY)" \
		"server_image=$(IMAGE)" \
		"server_image_version_alias=$(IMAGE_VERSION)" \
		"operator_image=$(OPERATOR_IMAGE)" \
		"operator_image_version_alias=$(OPERATOR_IMAGE_VERSION)" \
		"server_tar=$(notdir $(IMAGE_TAR))" \
		"operator_tar=$(notdir $(OPERATOR_TAR))" \
		"built_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		> $(IMAGE_BUILD_INFO)
	@printf "$(COLOR_GREEN)Wrote $(IMAGE_BUILD_INFO)$(COLOR_RESET)\n"
endef

container-export-all: container-export k8s-operator-export ## Export server + operator images as air-gap tarballs (+ build-info)
	$(call log,Air-gap image tarballs in $(IMAGE_EXPORT_DIR))
	$(write_image_build_info)
	@ls -lh $(IMAGE_EXPORT_DIR)/*$(IMAGE_TAG)* 2>/dev/null || ls -lh $(IMAGE_EXPORT_DIR)/ 2>/dev/null || true
	@printf "$(COLOR_GREEN)Standalone needs: $(notdir $(IMAGE_TAR))$(COLOR_RESET)\n"
	@printf "$(COLOR_GREEN)Kubernetes needs: $(notdir $(IMAGE_TAR)) + $(notdir $(OPERATOR_TAR)) (if using operator)$(COLOR_RESET)\n"
	@printf "$(COLOR_GREEN)Identify this build: IMAGE_TAG=$(IMAGE_TAG) commit=$(COMMIT)$(COLOR_RESET)\n"

# Deprecated aliases (prefer container-build / k8s-operator-build / container-build-all).
docker-build: container-build
docker-build-operator: k8s-operator-build
docker-build-all: container-build-all

build: ## Build statically linked release binary to $(BINARY)
	$(call log,Building static binary $(BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(MAIN_PKG)
	@file $(BINARY) | grep -q 'statically linked'
	@(ldd $(BINARY) 2>&1 || true) | grep -q 'not a dynamic executable'

build-cli: ## Build statically linked CLI binary to $(CLI_BINARY)
	$(call log,Building CLI binary $(CLI_BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(CLI_BINARY) $(CLI_PKG)

# Multi-platform knxvault-cli packages for GitHub Releases / air-gap admin hosts.
# (CLI_RELEASE_DIR is set with other BUILD_DIR paths above; default build/release/cli.)
package-cli-release: ## Cross-compile knxvault-cli packages → $(CLI_RELEASE_DIR)
	$(call log,Packaging multi-platform knxvault-cli release archives)
	$(call require_cmd,go)
	$(call require_cmd,bash)
	@VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_ID=$(BUILD_ID) \
		CLI_RELEASE_DIR=$(CLI_RELEASE_DIR) GO_TOOLCHAIN=$(GO_TOOLCHAIN) \
		bash scripts/package-cli-release.sh

build-csi: ## Build Secrets Store CSI provider binary
	$(call log,Building CSI provider $(CSI_BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(CSI_BINARY) $(CSI_PKG)

build-webhook: ## Build mutating admission webhook binary
	$(call log,Building webhook $(WEBHOOK_BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(WEBHOOK_BINARY) $(WEBHOOK_PKG)

build-eso: ## Build External Secrets Operator webhook adapter
	$(call log,Building ESO adapter $(ESO_BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(ESO_BINARY) $(ESO_PKG)

build-operator: ## Build knxvault-operator (cert-manager replacement CRDs)
	$(call log,Building operator $(OPERATOR_BINARY))
	$(call require_cmd,go)
	@mkdir -p $(BIN_DIR)
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

sbom: ## Generate CycloneDX SBOM (modules + release binary) under $(BUILD_DIR)
	@test -f $(BINARY) || $(MAKE) --no-print-directory build
	@mkdir -p $(BUILD_DIR)
	$(call log,Generating SBOM $(SBOM_FILE))
	$(call require_cmd,trivy)
	$(TRIVY) fs --cache-dir $(TRIVY_CACHE_DIR) \
		--format cyclonedx --output $(SBOM_FILE) .
	$(TRIVY) rootfs --cache-dir $(TRIVY_CACHE_DIR) \
		--format cyclonedx --output $(SBOM_BINARY_FILE) $(BINARY)
	@test -s $(SBOM_FILE)

scan: ## Trivy vulnerability scan (repo + binary if present)
	$(call log,Running Trivy filesystem scan)
	$(call require_cmd,trivy)
	@mkdir -p $(BUILD_DIR)
	$(TRIVY) fs --cache-dir $(TRIVY_CACHE_DIR) \
		--ignorefile .trivyignore \
		--severity $(TRIVY_SEVERITY) --exit-code 1 --scanners vuln .
	@# Rebuild when binary is missing or linked against an older stdlib than GO_TOOLCHAIN (CVE gates).
	@need_build=0; \
	if [ ! -f $(BINARY) ]; then need_build=1; \
	elif ! go version -m $(BINARY) 2>/dev/null | head -1 | grep -q "$$(echo $(GO_TOOLCHAIN) | sed 's/^go//')"; then need_build=1; fi; \
	if [ "$$need_build" = 1 ]; then $(MAKE) --no-print-directory build; fi
	@if [ -f $(BINARY) ]; then \
		$(TRIVY) rootfs --cache-dir $(TRIVY_CACHE_DIR) \
			--ignorefile .trivyignore \
			--severity $(TRIVY_SEVERITY) --exit-code 1 --scanners vuln $(BINARY); \
	fi

tidy: ## Run go mod tidy
	$(call log,Running go mod tidy)
	$(call require_cmd,go)
	$(GO) mod tidy

clean: ## Remove all build/ artifacts (binaries, images tarballs, SBOM, coverage)
	$(call log,Cleaning build artifacts under $(BUILD_DIR))
	@rm -rf $(BUILD_DIR) bin dist
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
	@printf "  $(COLOR_CYAN)BUILD_DIR$(COLOR_RESET)        = $(BUILD_DIR)\n"
	@printf "  $(COLOR_CYAN)VERSION$(COLOR_RESET)         = $(VERSION)\n"
	@printf "  $(COLOR_CYAN)COMMIT$(COLOR_RESET)          = $(COMMIT)\n"
	@printf "  $(COLOR_CYAN)IMAGE_TAG$(COLOR_RESET)       = $(IMAGE_TAG)\n"
	@printf "  $(COLOR_CYAN)IMAGE_REPOSITORY$(COLOR_RESET)= $(IMAGE_REPOSITORY)\n"
	@printf "  $(COLOR_CYAN)IMAGE$(COLOR_RESET)           = $(IMAGE)\n"
	@printf "  $(COLOR_CYAN)OPERATOR_IMAGE$(COLOR_RESET)  = $(OPERATOR_IMAGE)\n"
	@printf "  $(COLOR_CYAN)BINARY$(COLOR_RESET)          = $(BINARY)\n"
	@printf "  $(COLOR_CYAN)IMAGE_EXPORT_DIR$(COLOR_RESET)= $(IMAGE_EXPORT_DIR)\n"
	@printf "  $(COLOR_CYAN)IMAGE_TAR$(COLOR_RESET)       = $(IMAGE_TAR)\n"
	@printf "  $(COLOR_CYAN)SBOM_FILE$(COLOR_RESET)       = $(SBOM_FILE)\n"
	@printf "  $(COLOR_CYAN)TRIVY_SEVERITY$(COLOR_RESET)  = $(TRIVY_SEVERITY)\n"
	@printf "  $(COLOR_CYAN)TRIVY_CACHE_DIR$(COLOR_RESET) = $(TRIVY_CACHE_DIR)\n"
	@printf "  $(COLOR_CYAN)GO_TOOLCHAIN$(COLOR_RESET)    = $(GO_TOOLCHAIN)\n"
	@printf "\n$(COLOR_BOLD)Examples$(COLOR_RESET)\n\n"
	@printf "  make all\n"
	@printf "  make package-all    # images + multi-platform CLI (CI packaging parity)\n"
	@printf "  make build\n"
	@printf "  make clean\n"
	@printf "  make test\n"