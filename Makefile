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
check: tidy-check fmt-check lint test vuln awsstore ## Run the full CI gate locally (root + awsstore submodule)

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

# Discovery is per package, not per repo, because `go test -fuzz` accepts
# exactly one target in exactly one package: a repo-wide `-list` cannot say
# which package a FuzzXxx came from. Both modules in the workspace are walked,
# so a new target anywhere — qurl, relayknock/internal/nhpwire, awsstore — is
# soaked with no edit here and none in fuzz.yml. A package that fails to list
# is fatal rather than silently skipped, and zero targets repo-wide is fatal
# too: that only happens if discovery itself broke.
.PHONY: fuzz
fuzz: ## Run every fuzz target in the workspace for $(FUZZTIME) each (auto-discovered)
	@found=0; \
	for pkg in $$($(GO) list ./... ./awsstore/...); do \
		if ! listing=$$($(GO) test -list '^Fuzz' $$pkg); then \
			echo "cannot list fuzz targets in $$pkg"; exit 1; \
		fi; \
		for t in $$(printf '%s\n' "$$listing" | grep '^Fuzz' || true); do \
			found=1; \
			echo ">> $$pkg $$t"; \
			$(GO) test -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done; \
	if [ "$$found" != "1" ]; then echo "no fuzz targets found"; exit 1; fi

# awsstore is a SEPARATE module (github.com/layervai/qurl-go/awsstore) that
# isolates the AWS SDK v2 dependency, so the root `./...` targets above never
# reach it. This target mirrors the root gate (tidy, fmt, vet, lint, test -race,
# vuln) inside ./awsstore, reusing the same pinned tools. It builds against the
# in-tree parent via the committed go.work, so no parent tag is needed.
.PHONY: awsstore
awsstore: $(GOLANGCI) $(GOVULN) ## Run the full gate for the awsstore submodule
	cd awsstore && $(GO) mod tidy -diff
	cd awsstore && $(GOLANGCI) fmt --diff ./...
	cd awsstore && $(GO) vet ./...
	cd awsstore && $(GOLANGCI) run ./...
	cd awsstore && $(GO) test -race ./...
	cd awsstore && $(GOVULN) ./...

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
