.PHONY: build install uninstall-bin test integration eval lint secrets-check

EVAL_SCRIPT := ./evals/mcp_tool_choice/run.sh
PREFIX ?= /usr/local

build:
	go build -o twarp ./cmd/twarp

# Root-owned binary in $(PREFIX)/bin: sudo can find it, and the root geo
# daemon never executes a user-writable file. Build runs as the user so the
# Go cache stays in the user's home.
install: build
	sudo install -m 755 twarp $(PREFIX)/bin/twarp
	@echo "installed $(PREFIX)/bin/twarp; next: sudo twarp install"

uninstall-bin:
	sudo rm -f $(PREFIX)/bin/twarp

test:
	go test ./...

integration:
	go test -tags integration ./...

eval:
	@if [ ! -x $(EVAL_SCRIPT) ]; then \
		echo "eval: $(EVAL_SCRIPT) not found or not executable" >&2; \
		exit 1; \
	fi
	$(EVAL_SCRIPT)

lint:
	golangci-lint run --build-tags integration ./...
	shellcheck .githooks/pre-commit $(EVAL_SCRIPT) scripts/smoke.sh

# Scan both committed history and the working tree: the pre-commit hook runs
# before the new content exists in history.
secrets-check:
	gitleaks git --no-banner --config .gitleaks.toml .
	gitleaks dir --no-banner --config .gitleaks.toml .
