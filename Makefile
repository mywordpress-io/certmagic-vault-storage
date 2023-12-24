SHELL := /bin/bash

default: help
.PHONY: default

help: ## Display this help screen (default)
	@grep -h "##" $(MAKEFILE_LIST) | grep -vE '^#|grep' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' | sort
.PHONY: help

lint: ## Run linter against codebase
	@golangci-lint -v run
.PHONY: lint

fmt: ## Run go-fmt against codebase
	@go fmt ./...
.PHONY: fmt

mod-download: ## Download go modules
	@go mod download
.PHONY: mod-download

mod-tidy: ## Make sure go modules are tidy
	@go mod tidy
.PHONY: mod-tidy

mod-update: export MODULE ?=
mod-update: ## Update go proxy with latest module version: MODULE=github.com/mywordpress-io/certmagic-vault-storage@v0.1.1 make mod-update
	@if [[ -n "${MODULE}" ]]; then                       \
		GOPROXY=proxy.golang.org go list -m ${MODULE};   \
	else                                                 \
		echo "ERROR: Missing 'MODULE', cannot continue"; \
		exit 1;                                          \
	fi
.PHONY: mod-update
