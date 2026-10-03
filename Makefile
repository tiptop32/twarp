.PHONY: build test integration eval lint secrets-check

EVAL_SCRIPT := ./evals/mcp_tool_choice/run.sh

build:
	go build -o twarp ./cmd/twarp

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
	shellcheck .githooks/pre-commit $(EVAL_SCRIPT)

# Scan both committed history and the working tree: the pre-commit hook runs
# before the new content exists in history.
secrets-check:
	gitleaks git --no-banner --config .gitleaks.toml .
	gitleaks dir --no-banner --config .gitleaks.toml .
