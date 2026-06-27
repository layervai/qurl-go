# qurl-go developer tasks.
#
# `make check` is the single gate: it runs exactly what CI runs, so a green
# local check means a green CI. Tool versions are pinned in this file so every
# contributor and CI runner uses the same analyzers.

# Pinned tool versions. Bump deliberately; Dependabot/Renovate can PR these.
GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_VERSION   ?= v1.5.0

GO        ?= go
TOOLBIN   := $(CURDIR)/.tools
GOLANGCI  := $(TOOLBIN)/golangci-lint
GOVULN    := $(TOOLBIN)/govulncheck

# Fuzz smoke duration per target (CI). Override for longer local soak runs:
#   make fuzz FUZZTIME=2m
FUZZTIME ?= 20s

.DEFAULT_GOAL := check

.PHONY: check
check: tidy-check fmt-check lint test vuln ## Run the full CI gate locally

.PHONY: test
test: ## Run all tests with the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Run tests and write an HTML coverage report
	$(GO) test -race -coverprofile=coverage.txt -covermode=atomic ./...
	$(GO) tool cover -func=coverage.txt | tail -1
	$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "wrote coverage.html"

.PHONY: lint
lint: $(GOLANGCI) ## Run golangci-lint (lint + format check)
	$(GOLANGCI) run ./...

.PHONY: fmt
fmt: $(GOLANGCI) ## Apply formatters (gofumpt + goimports)
	$(GOLANGCI) fmt ./...

.PHONY: fmt-check
fmt-check: $(GOLANGCI) ## Fail if any file is not formatted
	$(GOLANGCI) fmt --diff ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: vuln
vuln: $(GOVULN) ## Scan for known vulnerabilities in called code
	$(GOVULN) ./...

.PHONY: fuzz
fuzz: ## Run every qv2 fuzz target for $(FUZZTIME) each (targets auto-discovered)
	@targets=$$($(GO) test -list '^Fuzz' ./qv2 | grep '^Fuzz'); \
	if [ -z "$$targets" ]; then echo "no fuzz targets found"; exit 1; fi; \
	for t in $$targets; do \
		echo ">> $$t"; \
		$(GO) test -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) ./qv2 || exit 1; \
	done

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod/go.sum are not tidy
	$(GO) mod tidy -diff

# --- tool installation (pinned, project-local under .tools/) ---

$(GOLANGCI):
	GOBIN=$(TOOLBIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULN):
	GOBIN=$(TOOLBIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: tools
tools: $(GOLANGCI) $(GOVULN) ## Install pinned dev tools into ./.tools

.PHONY: clean
clean: ## Remove build/test/tool artifacts
	rm -rf $(TOOLBIN) coverage.txt coverage.html

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
