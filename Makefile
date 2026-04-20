SHELL := /usr/bin/env bash

.PHONY: ci-local-dry-run ci-local-smoke ci-local-full ci-local-dry-run-ps ci-local-smoke-ps ci-local-full-ps

ci-local-dry-run:
	bash scripts/gitlab-ci-local-dry-run.sh --dry-run

ci-local-smoke:
	bash scripts/gitlab-ci-local-dry-run.sh --smoke

ci-local-full:
	bash scripts/gitlab-ci-local-dry-run.sh --full

ci-local-dry-run-ps:
	powershell -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode dry-run

ci-local-smoke-ps:
	powershell -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode smoke

ci-local-full-ps:
	powershell -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode full
