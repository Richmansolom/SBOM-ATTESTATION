#!/usr/bin/env bash
set -euo pipefail

# Local GitLab CI emulation helper.
# - --dry-run: print each stage command without executing.
# - --smoke: execute a fast local path that mirrors stage flow.
# - --full: execute a fuller local path (includes build/source+build SBOM generation).

MODE="dry-run"

while (($#)); do
  case "$1" in
    --dry-run)
      MODE="dry-run"
      shift
      ;;
    --smoke)
      MODE="smoke"
      shift
      ;;
    --full)
      MODE="full"
      shift
      ;;
    *)
      echo "Unknown arg: $1" >&2
      echo "Usage: $0 [--dry-run|--smoke|--full]" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-example-app}"
APP_METADATA="${APP_METADATA:-example-app/app-metadata.json}"
SBOM_DIR="${SBOM_DIR:-sbom}"
REPORT_DIR="${REPORT_DIR:-reports}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.69.3}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:latest}"
CYCLONEDX_IMAGE="${CYCLONEDX_IMAGE:-cyclonedx/cyclonedx-cli:latest}"
HOPPR_IMAGE="${HOPPR_IMAGE:-hoppr/hopctl:latest}"
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:latest}"

run_cmd() {
  if [[ "$MODE" == "dry-run" ]]; then
    echo "DRY-RUN: $*"
  else
    eval "$@"
  fi
}

require_tools() {
  local tool
  if [[ "$MODE" == "dry-run" ]]; then
    for tool in bash; do
      if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
      fi
    done
    return
  fi

  for tool in docker bash jq make; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "Missing required tool: $tool" >&2
      exit 1
    fi
  done
}

banner() {
  echo
  echo "========== $1 =========="
}

stage_build() {
  banner "build"
  run_cmd "bash \"$REPO_ROOT/scripts/clean-sbom-outputs.sh\" \"$SBOM_DIR\" \"$REPORT_DIR\""
  run_cmd "mkdir -p \"$REPO_ROOT/$SBOM_DIR\" \"$REPO_ROOT/$REPORT_DIR\" \"$REPO_ROOT/$APP_DIR/build\""
  run_cmd "make -C \"$REPO_ROOT/$APP_DIR\" 2>&1 | tee \"$REPO_ROOT/$REPORT_DIR/build-output.log\""
}

stage_generate() {
  banner "generate"
  run_cmd "docker pull \"$SYFT_IMAGE\""
  run_cmd "docker pull \"$TRIVY_IMAGE\""
  run_cmd "docker pull \"$CYCLONEDX_IMAGE\""
  run_cmd "docker pull python:3.12-slim"
  run_cmd "docker pull mcr.microsoft.com/powershell:7.4-ubuntu-22.04"

  run_cmd "docker run --rm -v \"$REPO_ROOT:/src\" \"$SYFT_IMAGE\" dir:/src/$APP_DIR -o cyclonedx-json > \"$REPO_ROOT/$SBOM_DIR/sbom-source-syft.json\""
  if [[ "$MODE" == "full" ]]; then
    run_cmd "docker run --rm -v \"$REPO_ROOT:/src\" \"$SYFT_IMAGE\" dir:/src/$APP_DIR/build -o cyclonedx-json > \"$REPO_ROOT/$SBOM_DIR/sbom-build-syft.json\""
  fi

  run_cmd "docker run --rm -v \"$REPO_ROOT:/src\" -v \"$REPO_ROOT:/work\" \"$TRIVY_IMAGE\" filesystem --format cyclonedx --output \"/work/$SBOM_DIR/sbom-source-trivy.json\" /src/$APP_DIR"
  if [[ "$MODE" == "full" ]]; then
    run_cmd "docker run --rm -v \"$REPO_ROOT:/src\" -v \"$REPO_ROOT:/work\" \"$TRIVY_IMAGE\" filesystem --format cyclonedx --output \"/work/$SBOM_DIR/sbom-build-trivy.json\" /src/$APP_DIR/build"
  fi

  run_cmd "docker run --rm -v \"$REPO_ROOT:/work\" python:3.12-slim bash -lc 'pip install --no-cache-dir distro2sbom >/dev/null && python -m distro2sbom.cli --distro auto --system --sbom cyclonedx --format json --product-type operating-system --product-name sbom-runtime --product-version 1.0 --output-file /work/$SBOM_DIR/sbom-distro2sbom.json'"

  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" merge --input-files \"/data/$SBOM_DIR/sbom-source-syft.json\" \"/data/$SBOM_DIR/sbom-source-trivy.json\" \"/data/$SBOM_DIR/sbom-distro2sbom.json\" --output-file \"/data/$SBOM_DIR/sbom-source.json\" --output-format json"
  run_cmd "docker run --rm -v \"$REPO_ROOT:/work\" -w /work mcr.microsoft.com/powershell:7.4-ubuntu-22.04 pwsh -File merge-sbom.ps1 -InputSbom \"$SBOM_DIR/sbom-source.json\" -AppMetadata \"$APP_METADATA\" -OutputSbom \"$SBOM_DIR/sbom-source.enriched.json\""

  if [[ "$MODE" == "full" ]]; then
    run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" merge --input-files \"/data/$SBOM_DIR/sbom-build-syft.json\" \"/data/$SBOM_DIR/sbom-build-trivy.json\" \"/data/$SBOM_DIR/sbom-distro2sbom.json\" --output-file \"/data/$SBOM_DIR/sbom-build.json\" --output-format json"
    run_cmd "docker run --rm -v \"$REPO_ROOT:/work\" -w /work mcr.microsoft.com/powershell:7.4-ubuntu-22.04 pwsh -File merge-sbom.ps1 -InputSbom \"$SBOM_DIR/sbom-build.json\" -AppMetadata \"$APP_METADATA\" -OutputSbom \"$SBOM_DIR/sbom-build.enriched.json\""
  fi
}

stage_validate() {
  banner "validate"
  run_cmd "docker pull \"$HOPPR_IMAGE\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" validate --input-file \"/data/$SBOM_DIR/sbom-source.enriched.json\" | tee \"$REPO_ROOT/$REPORT_DIR/cyclonedx-validate-source.txt\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/work\" -w /work mcr.microsoft.com/powershell:7.4-ubuntu-22.04 pwsh -File ./check-ntia.ps1 -SbomFile \"$SBOM_DIR/sbom-source.enriched.json\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" -w /data \"$HOPPR_IMAGE\" validate sbom --sbom \"$SBOM_DIR/sbom-source.enriched.json\" --profile ntia --log \"/data/$REPORT_DIR/hoppr-source.log\" --output-file \"/data/$REPORT_DIR/hoppr-source-results.json\" --basic-term | tee \"$REPO_ROOT/$REPORT_DIR/hoppr-source-console.txt\""
  if [[ "$MODE" == "full" ]]; then
    run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" validate --input-file \"/data/$SBOM_DIR/sbom-build.enriched.json\" | tee \"$REPO_ROOT/$REPORT_DIR/cyclonedx-validate-build.txt\""
  fi
}

stage_sign() {
  banner "sign"
  run_cmd "chmod +x \"$REPO_ROOT/scripts/sign-sbom.sh\""
  run_cmd "mkdir -p \"$REPO_ROOT/$SBOM_DIR/pki\""
  run_cmd "cp \"$REPO_ROOT/$SBOM_DIR/sbom-source.enriched.json\" \"$REPO_ROOT/$SBOM_DIR/sbom-source.enriched.unsigned.json\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" convert --input-file \"/data/$SBOM_DIR/sbom-source.enriched.unsigned.json\" --output-file \"/data/$SBOM_DIR/sbom-source.enriched.unsigned.v16.json\" --output-format json --output-version v1_6"
  run_cmd "bash \"$REPO_ROOT/scripts/sign-sbom.sh\" \"$REPO_ROOT/$SBOM_DIR/sbom-source.enriched.json\" \"$REPO_ROOT/$SBOM_DIR/sbom-source.enriched.json\" \"$REPO_ROOT/$SBOM_DIR/pki\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$CYCLONEDX_IMAGE\" validate --input-file \"/data/$SBOM_DIR/sbom-source.enriched.json\" | tee \"$REPO_ROOT/$REPORT_DIR/cyclonedx-signed-validate-source.txt\""
}

stage_scan() {
  banner "scan"
  run_cmd "docker pull \"$GRYPE_IMAGE\""
  run_cmd "mkdir -p \"$REPO_ROOT/.cache/grype-db\""
  run_cmd "docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v \"$REPO_ROOT/.cache/grype-db:/grype-db\" \"$GRYPE_IMAGE\" db update > \"$REPO_ROOT/$REPORT_DIR/grype-db-update.txt\" 2>&1"
  run_cmd "docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v \"$REPO_ROOT/.cache/grype-db:/grype-db\" \"$GRYPE_IMAGE\" db status > \"$REPO_ROOT/$REPORT_DIR/grype-db-status.txt\" 2>&1"
  run_cmd "docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v \"$REPO_ROOT/.cache/grype-db:/grype-db\" \"$GRYPE_IMAGE\" db providers > \"$REPO_ROOT/$REPORT_DIR/grype-db-providers.txt\" 2>&1"
  run_cmd "docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v \"$REPO_ROOT:/data\" -v \"$REPO_ROOT/.cache/grype-db:/grype-db\" \"$GRYPE_IMAGE\" sbom:/data/$SBOM_DIR/sbom-source.enriched.unsigned.v16.json -o json > \"$REPO_ROOT/$REPORT_DIR/grype-report.json\""
  run_cmd "docker run --rm -e GRYPE_DB_CACHE_DIR=/grype-db -v \"$REPO_ROOT:/data\" -v \"$REPO_ROOT/.cache/grype-db:/grype-db\" \"$GRYPE_IMAGE\" sbom:/data/$SBOM_DIR/sbom-source.enriched.unsigned.v16.json -o table > \"$REPO_ROOT/$REPORT_DIR/grype-report.txt\""
  run_cmd "docker run --rm -v \"$REPO_ROOT:/data\" \"$TRIVY_IMAGE\" sbom --scanners vuln --vuln-severity-source nvd,ghsa,osv --format json --output \"/data/$REPORT_DIR/trivy-sbom-report.json\" \"/data/$SBOM_DIR/sbom-source.enriched.unsigned.v16.json\""
}

stage_report() {
  banner "report"
  run_cmd "jq -r 'def count(sev): ([ .matches[]? | select(.vulnerability.severity == sev) ] | length); \"Vulnerability Analysis Summary\", \"==============================\", (\"Total: \" + ([ .matches[]? ] | length | tostring)), (\"Critical: \" + (count(\"Critical\") | tostring)), (\"High: \" + (count(\"High\") | tostring)), (\"Medium: \" + (count(\"Medium\") | tostring)), (\"Low: \" + (count(\"Low\") | tostring))' \"$REPO_ROOT/$REPORT_DIR/grype-report.json\" > \"$REPO_ROOT/$REPORT_DIR/vulnerability-analysis.txt\""
  run_cmd "echo \"Local stage emulation complete.\" >> \"$REPO_ROOT/$REPORT_DIR/vulnerability-analysis.txt\""
}

main() {
  cd "$REPO_ROOT"
  require_tools

  echo "Mode: $MODE"
  echo "Repo: $REPO_ROOT"
  echo "App:  $APP_DIR"

  stage_build
  stage_generate
  stage_validate
  stage_sign
  stage_scan
  stage_report

  if [[ "$MODE" == "dry-run" ]]; then
    echo
    echo "Dry-run complete. Use '--smoke' for one-command local execution."
  else
    echo
    echo "Execution complete. Review artifacts under '$SBOM_DIR/' and '$REPORT_DIR/'."
  fi
}

main "$@"
