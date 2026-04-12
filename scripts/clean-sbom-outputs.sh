#!/usr/bin/env bash
# Remove generated SBOM JSON/tar at repo sbom root and all report files so local/CI runs
# never mix new scans with leftover artifacts. Preserves sbom/pki/ and other subdirs.
set -euo pipefail
SBOM_DIR="${1:-sbom}"
REPORT_DIR="${2:-reports}"
mkdir -p "$SBOM_DIR" "$REPORT_DIR"
if [ -d "$REPORT_DIR" ]; then
  find "$REPORT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi
mkdir -p "$REPORT_DIR"
if [ -d "$SBOM_DIR" ]; then
  find "$SBOM_DIR" -maxdepth 1 -type f \( -name '*.json' -o -name '*.tar' \) -delete
fi
