# Software Bill of Materials (SBOM) Attestation

This repository is a reusable reference implementation for generating, validating, signing, and scanning SBOMs for C/C++ software using COTS tooling plus project metadata.

## Goal

Enable another engineer or team to clone this repo, point it at their own C/C++ application, and produce the same class of outputs:

- CycloneDX SBOMs (source/build/container-aware)
- NTIA minimum-elements evidence (local + Hoppr)
- Signed SBOM with verifiable cryptographic signature
- Vulnerability evidence from Grype and Trivy (with DB freshness artifacts)
- CI/CD pipeline artifacts from both GitHub and GitLab

## Reference Architecture

The implementation uses a staged model:

1. Build target application
2. Generate raw SBOMs with COTS tools
3. Enrich SBOM using app metadata
4. Validate SBOM structure and NTIA completeness
5. Sign SBOM and verify signature
6. Run vulnerability scans and produce summary report
7. Publish artifacts and logs for auditability

## Repository Structure

```text
sbom-attestation/
|-- example-app/                         # Reference C++ target app
|   |-- src/                             # C++ sources
|   |-- include/                         # Headers
|   |-- Dockerfile                       # Container build path
|   |-- Makefile                         # Native build path
|   `-- app-metadata.json                # Custom component metadata
|-- scripts/
|   `-- sign-sbom.sh                     # Canonicalize + sign + embed signature
|-- sbom/                                # Generated SBOM outputs and PKI artifacts
|-- reports/                             # Validation, scan, and DB evidence outputs
|-- sbom_ui/
|   |-- app.py                           # Flask API (generate/sign/scan + pipeline APIs)
|   |-- requirements.txt
|   `-- static/index.html                # Mission Control UI frontend
|-- generate-sbom.ps1                    # Local orchestrator (native/container mode)
|-- merge-sbom.ps1                       # Inject custom app metadata into SBOM
|-- check-ntia.ps1                       # NTIA minimum-elements check
|-- .github/workflows/sbom-pipeline.yml  # GitHub Actions pipeline
|-- .gitlab-ci.yml                       # GitLab CI pipeline
|-- start-ui-local.ps1                   # Local UI starter on port 80
`-- README.md
```

## Toolchain and Roles

| Tool | Role in pipeline |
|---|---|
| Syft | Primary SBOM generation for source/filesystem/container |
| CycloneDX CLI | Convert/merge/validate CycloneDX documents |
| Distro2SBOM | Distribution package SBOM coverage |
| Hoppr | NTIA profile-based SBOM validation |
| Grype | SBOM vulnerability scan + DB status evidence |
| Trivy | Secondary SBOM vulnerability scan + DB metadata |
| OpenSSL | Key generation and signature verification |

## Prerequisites

Minimum for local reproducibility:

- PowerShell 7+
- Docker Desktop (or Podman)
- Python 3.10+ (for UI backend)
- GNU Make and a C++ compiler (for `example-app`)

Optional but recommended:

- GitHub CLI (`gh`) for GitHub pipeline integration in UI backend

## Quick Start (Local)

### 1) Clone and install UI dependencies

```powershell
git clone https://github.com/Richmansolom/SBOM-ATTESTATION.git
cd .\SBOM-ATTESTATION
python -m pip install -r .\sbom_ui\requirements.txt
```

### 2) Build the reference C++ app

```powershell
cd .\example-app
make
.\build\sbom_demo_app.exe
cd ..
```

### 3) Generate SBOM and evidence

Native mode:

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode native
```

Container mode:

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode container
```

Podman mode:

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode native -ContainerRuntime podman
```

### 4) Verify expected outputs

After a successful run, confirm these key files exist:

- `sbom/sbom-source.enriched.json`
- `sbom/pki/sbom_public_key.pem`
- `reports/cyclonedx-validate.txt`
- `reports/hoppr-ntia.log`
- `reports/grype-report.json`
- `reports/trivy-sbom-report.json`
- `reports/vulnerability-analysis.txt`
- `reports/grype-db-status.txt`

## Mission Control UI

Run locally:

```powershell
python .\sbom_ui\app.py
```

Open:

- `http://127.0.0.1:5000`

Optional local vanity URL:

1. Add to hosts file as Administrator:
   - `127.0.0.1 www.sbomcontrol.com`
2. Start UI on port 80:
   - `pwsh -ExecutionPolicy Bypass -File .\start-ui-local.ps1`
3. Open:
   - `http://www.sbomcontrol.com`

### UI Provider Modes (GitHub + GitLab)

The UI supports both providers:

- GitHub Actions mode
- GitLab CI mode

Connect modal fields:

- Provider: `github` or `gitlab`
- Project path: `namespace/project`
- Access token: optional for public read; often required for pipeline trigger

## CI/CD Parity

### GitHub

Workflow: `.github/workflows/sbom-pipeline.yml`

Stages include:

- Build
- Generate
- Sign
- Scan
- Report

### GitLab

Workflow: `.gitlab-ci.yml`

Implements the same logical stages and artifacts as GitHub.

## Attestation and Validation Model

This implementation combines multiple validation layers:

1. CycloneDX structural validation
2. NTIA minimum-elements validation (`check-ntia.ps1`)
3. Hoppr NTIA profile validation
4. Signature generation and verification
5. Dual vulnerability scanner cross-check (Grype + Trivy)
6. Vulnerability DB freshness evidence capture

## Required Artifact Set for Reproducibility

If another team wants to claim "same implementation class", they should produce and retain:

- Enriched SBOM (`sbom-source.enriched.json`)
- Signed SBOM and signature/public-key evidence
- NTIA check output (`reports/ntia-summary.txt` when available)
- Hoppr output (`reports/hoppr-ntia.log`, `reports/hoppr-ntia-results.json`)
- Grype report and DB status/provider files
- Trivy report and DB status/update evidence
- Combined vulnerability summary report

## How to Adapt This for Another C/C++ Project

1. Replace `example-app/` with your project path
2. Update metadata source (`app-metadata.json`) with your:
   - supplier
   - component names
   - versions
   - dependency relationships
3. Ensure build command in CI and local scripts matches your build system
4. Keep SBOM output names stable to preserve downstream tooling/UI compatibility
5. Re-run local generation and confirm artifact set
6. Run CI on both GitHub and GitLab and compare outputs

## Quality Gate Checklist

Use this checklist before accepting a run:

- Build succeeds
- SBOM generated for intended target
- Enrichment merged correctly
- CycloneDX validation passes
- NTIA checks pass (script + Hoppr)
- Signature verification passes
- Grype and Trivy reports generated
- DB status files generated and fresh
- Artifacts uploaded and downloadable

## Free Hosting (Optional)

- Frontend: GitHub Pages (`sbom_ui/static`)
- Backend API: Render (`sbom_ui/app.py`)

See `FREE_HOSTING_SETUP.md` for deployment wiring using `?api=https://...`.

## Security Notes

- Never commit private signing keys
- Keep branch protections enabled for production branches
- Use least-privilege tokens for pipeline triggers
- Treat generated vulnerability reports as sensitive operational data

## Data Usage and Management Plan (Current Pipeline)

All SBOM outputs are treated as sensitive software supply-chain records. The following reflects the repository's current behavior and CI configuration.

- **Source code authority:** GitHub (`Richmansolom/SBOM-ATTESTATION`) is the primary maintained source. GitLab is kept aligned through sync updates (direct push when allowed, or protected-branch merge request flow).
- **SBOM artifacts:** SBOM files under `sbom/` are published as CI artifacts in both GitHub Actions and GitLab CI.
- **Artifact retention:** Current retention is **7 days** (GitHub `retention-days: 7`, GitLab `expire_in: 1 week`), not three months.
- **Vulnerability reports:** Grype and Trivy outputs are archived in `reports/` (JSON and table/text outputs, plus `vulnerability-analysis.txt`, and DB status/update/provider evidence). HTML vulnerability reports are not currently produced by default.
- **Cryptographic keys:** `scripts/sign-sbom.sh` currently generates an RSA keypair in `sbom/pki/` at runtime if keys do not exist. Because CI artifacts include `sbom/`, private key material can be present in artifacts unless explicitly excluded. This is functional for demo/testing but should be hardened for production.
- **Credentials and tokens:** The UI stores connection config in browser `sessionStorage` (`sbom_cfg`). If provided, tokens are sent only to this backend via `X-SBOM-TOKEN` for provider API calls. Tokens are optional for public read operations and are typically required for protected trigger operations.
- **External data flows:** SBOM processing/scanning is executed locally in runner containers. The pipeline does pull vulnerability databases and container images from upstream registries (for example, Grype DB and Trivy DB sources).
- **PII handling:** The pipeline and UI are designed for software/component metadata and do not intentionally collect or process personally identifiable information (PII).

## License

MIT
