# mcp-core top-level Makefile.
#
# Wraps the e2e driver under scripts/e2e/. The driver is a uv-managed Python
# sub-project; targets here resolve dependencies + delegate.

.PHONY: e2e-t0 e2e-full e2e-config bootstrap-skret

E2E_DIR := scripts/e2e

e2e-t0:
	cd $(E2E_DIR) && uv run python -m e2e.driver t0

e2e-full:
	cd $(E2E_DIR) && uv run python -m e2e.driver all

e2e-config:
	@if [ -z "$(CONFIG)" ]; then \
		echo "Usage: make e2e-config CONFIG=<id>"; exit 1; \
	fi
	cd $(E2E_DIR) && uv run python -m e2e.driver $(CONFIG)

bootstrap-skret:
	bash $(E2E_DIR)/bootstrap_skret.sh
