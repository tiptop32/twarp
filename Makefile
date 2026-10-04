.PHONY: build install uninstall-bin test integration eval eval-config-deployment eval-launchd-geo lint secrets-check

GEO_EVAL_SCRIPT := ./evals/launchd_geo/run.sh
EVAL_SCRIPTS := ./evals/config_deployment/run.sh ./evals/gateway_state_recovery/run.sh ./evals/lifecycle/run.sh ./evals/mcp_tool_choice/run.sh
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
	bash scripts/test-make-eval.sh

integration:
	go test -tags integration ./...

eval:
	@for script in $(EVAL_SCRIPTS); do \
		if [ ! -x "$$script" ]; then \
			echo "eval: $$script not found or not executable" >&2; \
			exit 1; \
		fi; \
		"$$script" || exit 1; \
	done

eval-launchd-geo:
	@if [ ! -x $(GEO_EVAL_SCRIPT) ]; then \
		echo "eval: $(GEO_EVAL_SCRIPT) not found or not executable" >&2; \
		exit 1; \
	fi
	$(GEO_EVAL_SCRIPT)

eval-config-deployment:
	./evals/config_deployment/run.sh

lint:
	golangci-lint run --build-tags integration ./...
	shellcheck .githooks/pre-commit $(EVAL_SCRIPTS) $(GEO_EVAL_SCRIPT) scripts/smoke.sh scripts/test-make-eval.sh

# Scan both committed history and the working tree: the pre-commit hook runs
# before the new content exists in history.
secrets-check:
	gitleaks git --no-banner --config .gitleaks.toml .
	gitleaks dir --no-banner --config .gitleaks.toml .
