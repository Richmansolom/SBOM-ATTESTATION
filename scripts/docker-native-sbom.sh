#!/usr/bin/env bash
# CI-parity SBOM + vulnerability scan using Docker only (no host PowerShell).
# Mirrors generate-sbom.ps1 native mode: Syft + Trivy + Distro2SBOM + merge + Grype + Trivy vuln.
set -euo pipefail

: "${REPO_ROOT:?REPO_ROOT required}"
: "${SOURCE_PATH:?SOURCE_PATH required}"
: "${APP_METADATA_PATH:?APP_METADATA_PATH required}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.69.3}"
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:latest}"

cd "$REPO_ROOT"
mkdir -p sbom reports ".cache/grype-db"

SRC_ABS="${REPO_ROOT}/${SOURCE_PATH}"
META_ABS="${REPO_ROOT}/${APP_METADATA_PATH}"

if [[ ! -d "$SRC_ABS" ]]; then
  echo "docker-native-sbom: source directory not found: $SRC_ABS" >&2
  exit 1
fi
if [[ ! -f "$META_ABS" ]]; then
  echo "docker-native-sbom: app metadata not found: $META_ABS" >&2
  exit 1
fi

echo "==> docker-native-sbom: Syft (dir scan)"
docker run --rm -v "${SRC_ABS}:/src:ro" anchore/syft:latest dir:/src -o cyclonedx-json > sbom/sbom-source-syft.json

echo "==> docker-native-sbom: Trivy filesystem (CycloneDX)"
docker run --rm -v "${SRC_ABS}:/src:ro" -v "${REPO_ROOT}:/work" "${TRIVY_IMAGE}" \
  filesystem --quiet --format cyclonedx --output "/work/sbom/sbom-source-trivy.json" /src

echo "==> docker-native-sbom: Distro2SBOM"
docker run --rm -v "${REPO_ROOT}:/work" python:3.12-slim bash -lc \
  'export PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1
   pip install --no-cache-dir -q distro2sbom >/dev/null
   python -m distro2sbom.cli --distro auto --system --sbom cyclonedx --format json \
   --product-type operating-system --product-name sbom-runtime --product-version 1.0 \
   --output-file /work/sbom/sbom-distro2sbom.json'

echo "==> docker-native-sbom: CycloneDX merge (Syft + Trivy + Distro)"
docker run --rm -v "${REPO_ROOT}:/data" cyclonedx/cyclonedx-cli:latest merge \
  --input-files /data/sbom/sbom-source-syft.json /data/sbom/sbom-source-trivy.json /data/sbom/sbom-distro2sbom.json \
  --output-file /data/sbom/sbom-source.cots-merged.json --output-format json

echo "==> docker-native-sbom: merge-sbom.ps1 (PowerShell in container)"
docker run --rm -v "${REPO_ROOT}:/work" -w /work mcr.microsoft.com/powershell:7.4-ubuntu-22.04 \
  pwsh -ExecutionPolicy Bypass -File /work/merge-sbom.ps1 \
  -InputSbom "/work/sbom/sbom-source.cots-merged.json" \
  -AppMetadata "/work/${APP_METADATA_PATH}" \
  -OutputSbom "/work/sbom/sbom-source.enriched.json"

echo "==> docker-native-sbom: CycloneDX convert to v1.6 (scanner compatibility)"
docker run --rm -v "${REPO_ROOT}:/data" cyclonedx/cyclonedx-cli:latest convert \
  --input-file=/data/sbom/sbom-source.enriched.json \
  --output-file=/data/sbom/sbom-source.enriched.unsigned.v16.json \
  --output-format json --output-version v1_6

GRYPE_CACHE="${REPO_ROOT}/.cache/grype-db"
mkdir -p "$GRYPE_CACHE"

echo "==> docker-native-sbom: Grype DB update"
docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v "${GRYPE_CACHE}:/grype-db" "${GRYPE_IMAGE}" db update
docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v "${GRYPE_CACHE}:/grype-db" "${GRYPE_IMAGE}" db status 2>&1 | tee reports/grype-db-status.txt || true

echo "==> docker-native-sbom: Grype SBOM scan"
docker run --rm -v "${REPO_ROOT}:/data" -e GRYPE_DB_CACHE_DIR=/grype-db -v "${GRYPE_CACHE}:/grype-db" "${GRYPE_IMAGE}" \
  "sbom:/data/sbom/sbom-source.enriched.unsigned.v16.json" -o json > reports/grype-report.json

echo "==> docker-native-sbom: Trivy SBOM vulnerability scan"
docker run --rm -v "${REPO_ROOT}:/data" "${TRIVY_IMAGE}" sbom \
  --scanners vuln --vuln-severity-source nvd,ghsa,osv \
  --format json --output "/data/reports/trivy-sbom-report.json" \
  "/data/sbom/sbom-source.enriched.unsigned.v16.json"

echo "==> docker-native-sbom: OK"
