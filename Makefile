SHELL := /usr/bin/env bash
POWERSHELL := $(shell command -v pwsh 2>/dev/null || command -v powershell 2>/dev/null)

.PHONY: ci-local-dry-run ci-local-smoke ci-local-full ci-local-dry-run-ps ci-local-smoke-ps ci-local-full-ps

ci-local-dry-run:
	bash scripts/gitlab-ci-local-dry-run.sh --dry-run

ci-local-smoke:
	bash scripts/gitlab-ci-local-dry-run.sh --smoke

ci-local-full:
	bash scripts/gitlab-ci-local-dry-run.sh --full

ci-local-dry-run-ps:
	@test -n "$(POWERSHELL)" || (echo "Missing PowerShell: install pwsh (recommended) or powershell" && exit 1)
	$(POWERSHELL) -ExecutionPolicy Bypass -File ./scripts/gitlab-ci-local-dry-run.ps1 -Mode dry-run

ci-local-smoke-ps:
	@test -n "$(POWERSHELL)" || (echo "Missing PowerShell: install pwsh (recommended) or powershell" && exit 1)
	$(POWERSHELL) -ExecutionPolicy Bypass -File ./scripts/gitlab-ci-local-dry-run.ps1 -Mode smoke

ci-local-full-ps:
	@test -n "$(POWERSHELL)" || (echo "Missing PowerShell: install pwsh (recommended) or powershell" && exit 1)
	$(POWERSHELL) -ExecutionPolicy Bypass -File ./scripts/gitlab-ci-local-dry-run.ps1 -Mode full
