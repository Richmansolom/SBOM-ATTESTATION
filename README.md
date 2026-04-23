# SBOM Attestation

Reference implementation for generating, enriching, validating, signing, and scanning CycloneDX SBOMs for C/C++ projects.

## What this repository provides

- Local SBOM pipeline with PowerShell: generate, validate, sign, scan, and summarize.
- Metadata enrichment using JSON, CSV, or XML app metadata.
- NTIA checks with both local script and Hoppr profile validation.
- Mission Control web UI for local operations and GitHub/GitLab pipeline launch/monitor.
- CI pipelines for GitHub Actions and GitLab CI with artifact bundles.

## Repository layout

```text
.
|-- example-app/                      # Sample C++ project + app-metadata.*
|-- test-apps/                        # Additional sample app targets
|-- sbom_ui/                          # Flask API + Mission Control UI
|-- viewer/                           # Static SBOM/Grype viewer
|-- scripts/                          # Sign, clean, setup, CI helper scripts
|-- generate-sbom.ps1                 # Local end-to-end SBOM pipeline
|-- merge-sbom.ps1                    # Merge custom metadata into CycloneDX SBOM
|-- check-ntia.ps1                    # NTIA minimum-elements check
|-- start-ui-local.ps1                # Local UI launcher (auto port selection)
|-- .github/workflows/sbom-pipeline.yml
|-- .gitlab-ci.yml
`-- README.md
```

## Prerequisites

Required for local runs:

- PowerShell 7+ (`pwsh`)
- Docker Desktop or Podman
- Python 3.10+ (for UI backend)
- C++ build toolchain + `make` (for sample app)

Optional:

- GitHub CLI (`gh`) fallback for triggering GitHub workflows from backend when token is not configured

## Quick start (local)

1. Install UI dependencies:

```powershell
python -m pip install -r .\sbom_ui\requirements.txt
```

2. Run local SBOM pipeline (native source scan):

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode native
```

3. Run local SBOM pipeline (container mode):

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode container
```

4. Optional: use a different app folder and metadata file:

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode native -SourcePath my-app -AppMetadataPath my-app/app-metadata.json
```

Notes:

- The pipeline cleans old generated outputs by default (`sbom/*.json`, `reports/*`).
- Use `-NoClean` only when intentionally preserving previous outputs.

## Expected outputs

After a successful local run, key outputs include:

- `sbom/sbom-source.enriched.json` (or `sbom/sbom-image.enriched.json` in container mode)
- `sbom/*unsigned*.json` conversion files for scanner compatibility
- `sbom/pki/sbom_public_key.pem` and signature artifacts
- `reports/cyclonedx-validate.txt`
- `reports/hoppr-ntia.log`
- `reports/grype-report.json`
- `reports/trivy-sbom-report.json`
- `reports/vulnerability-analysis.txt`

## Mission Control UI

Start locally (recommended on Windows):

```powershell
pwsh -ExecutionPolicy Bypass -File .\start-ui-local.ps1
```

Alternative:

```powershell
python .\sbom_ui\app.py
```

Then open the printed local URL (for example `http://127.0.0.1:5000/`).

### Launching GitHub/GitLab pipelines from UI

In the Connect modal, set:

- Provider (`github` or `gitlab`)
- Project (`owner/repo` for GitHub, `group/project` for GitLab)
- API Base URL (if using remote backend)
- Access token (if required)

GitHub trigger requirement:

- Use a Personal Access Token with workflow dispatch permission (`workflow` on classic PAT, or Actions write on fine-grained token).
- The auto-generated GitHub Actions `GITHUB_TOKEN` cannot dispatch workflows and returns 403 (`Resource not accessible by integration`).

## CI pipelines

### GitHub Actions

Workflow: `.github/workflows/sbom-pipeline.yml`

- Supports `workflow_dispatch` with inputs:
	- `app_path`
	- `app_version`
- Produces two artifacts:
	- `sbom-pipeline-essential`
	- `sbom-pipeline-evidence`
- Artifact retention: 7 days

### GitLab CI

Workflow: `.gitlab-ci.yml`

- Stages: Build -> Generate -> Validate -> Sign -> Scan -> Report
- Uses default variables `APP_DIR=example-app`, `APP_METADATA=example-app/app-metadata.json`
- Artifact retention: 1 week

### Local GitLab CI dry-run helpers

```bash
make ci-local-dry-run
make ci-local-smoke
make ci-local-full
```

PowerShell wrappers are also available in the same Makefile.

## Metadata formats

`merge-sbom.ps1` supports:

- JSON (`app-metadata.json`)
- CSV (`app-metadata.csv`)
- XML (`app-metadata.xml`)

You can include custom component graphs via metadata and they will be merged into the final CycloneDX SBOM.

## Current implementation status

The following is implemented and validated in this repository:

- SBOM generation: Syft + Trivy + Distro2SBOM are merged via CycloneDX for source/build targets.
- Metadata enrichment: custom C/C++ application metadata is merged into generated SBOMs.
- Validation: CycloneDX schema checks, local NTIA checks, and Hoppr NTIA validation are in place.
- Attestation: embedded SBOM signature generation and verification are implemented via OpenSSL-based flow.
- Vulnerability analysis: Grype and Trivy scans produce JSON/table outputs and combined summary evidence.
- Mission Control UI: Flask-served UI and APIs support GitHub/GitLab trigger and monitoring workflows.
- Security hardening: CI supports `SBOM_PRIVATE_KEY_PEM` injection and excludes private key material from uploaded artifacts.

## Real-world threat relevance

Security tooling is part of the software supply chain and can itself be targeted. This repository reflects that operational reality with the following controls:

- Prefer pinned scanner references where possible.
- Treat CI credentials and tokens as high-risk secrets and apply least privilege.
- Keep signing key material out of artifacts and inject keys via protected CI variables.
- Preserve auditable evidence (validation logs, scan outputs, DB status) for incident response and attestation.

## Attestation and validation model

This implementation combines multiple layers:

1. CycloneDX structural validation
2. NTIA minimum-elements validation (`check-ntia.ps1`)
3. Hoppr NTIA profile validation
4. Signature generation and verification
5. Dual vulnerability scanner cross-check (Grype + Trivy)
6. Vulnerability DB freshness evidence capture

## Required artifact set for reproducibility

For another team to reproduce this implementation class, retain at minimum:

- Enriched SBOMs (`sbom-source.enriched.json`, `sbom-build.enriched.json`, or image variant in container mode)
- Signed SBOM and signature/public-key evidence
- NTIA check output
- Hoppr output (`reports/hoppr-ntia.log`, `reports/hoppr-ntia-results.json`)
- Grype report and DB status/provider files
- Trivy report and DB update/status evidence
- Combined vulnerability summary (`reports/vulnerability-analysis.txt`)

CI publishes two bundles:

- `essential`: quick-consumption bundle for scanners, UI flows, and reviewer handoff
- `evidence`: full audit bundle with raw logs, DB freshness artifacts, validation logs, and supporting reports

## How to adapt this to another C/C++ project

1. Replace `example-app/` with your project (or point `APP_DIR` / `-SourcePath` at your tree).
2. Update metadata (`app-metadata.json`, `.csv`, or `.xml`) for supplier identity, application info, and optional `custom_components` graph.
3. Set `APP_DIR` and `APP_METADATA` in GitHub workflow and GitLab CI to match your project paths.
4. Replace the build command if you do not use Make (for example CMake or Ninja).
5. For local runs, use `generate-sbom.ps1` with `-SourcePath` and `-AppMetadataPath` as needed.
6. Keep SBOM/report output naming stable if downstream automation or UI flows depend on those paths.
7. Re-run pipeline after `git pull`; use `-NoClean` only for intentional debugging.

## Quality gate checklist

- Build succeeds
- SBOM generated for intended target
- Metadata enrichment merged correctly
- CycloneDX validation passes
- NTIA checks pass (local + Hoppr)
- Signature verification passes
- Grype and Trivy reports are generated
- DB status evidence is present and current
- Artifacts are uploaded and downloadable

## Data usage and management (current pipeline)

All generated SBOM and scan outputs should be handled as sensitive supply-chain records.

- Source authority: GitHub repository is primary; GitLab pipeline mirrors are supported.
- Artifact publication: `sbom/` and `reports/` outputs are included in CI artifact bundles.
- Retention: GitHub Actions uses 7-day retention; GitLab CI uses 1-week retention.
- Vulnerability reports: Grype/Trivy JSON and text outputs are archived under `reports/`.
- Cryptographic keys: signing keys can be injected via `SBOM_PRIVATE_KEY_PEM`; private key upload is excluded from CI artifacts.
- Credentials and tokens: UI can pass provider tokens to backend via `X-SBOM-TOKEN`; use least-privilege tokens.
- External data flows: pipeline pulls scanner images and vulnerability databases from upstream registries.
- PII: pipeline is designed for software/component metadata and does not intentionally process PII.

## Troubleshooting

### CycloneDX license validation errors

If you see messages like "license id should match enum", the source tools likely emitted non-SPDX license tokens.

- `merge-sbom.ps1` now normalizes known aliases and avoids writing unknown tokens as `license.id`.
- Unknown/non-standard values are emitted as `license.name`, which is valid CycloneDX.

### UI launch returns 403 on GitHub

Use a PAT in Connect modal. Do not rely on workflow `GITHUB_TOKEN` for dispatch.

### Wrong API endpoint saved in browser

Open `/?reset_api=1` on your UI URL to clear saved API base.

## Security notes

- Do not commit private signing keys.
- In CI, use `SBOM_PRIVATE_KEY_PEM` secret injection when signing with a managed key.
- Least privilege for API tokens.

## License

MIT
