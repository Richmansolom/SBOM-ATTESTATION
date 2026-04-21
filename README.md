# Software Bill of Materials (SBOM) Attestation

This repository is a reusable reference implementation for generating, validating, signing, and scanning SBOMs for C/C++ software using COTS tooling plus project metadata.

## Goal

Enable another engineer or team to clone this repo, point it at their own C/C++ application, and produce the same class of outputs:

- CycloneDX SBOMs (source/build/container-aware)
- NTIA minimum-elements evidence (local + Hoppr)
- Signed SBOM with verifiable cryptographic signature
- Vulnerability evidence from Grype and Trivy (with DB freshness artifacts)
- CI/CD pipeline artifacts from both GitHub and GitLab

## Clone this repository

Primary (GitHub):

```bash
git clone https://github.com/Richmansolom/SBOM-ATTESTATION.git
cd SBOM-ATTESTATION
```

Mirror (GitLab):

```bash
git clone https://gitlab.com/Richmansolom/SBOM-ATTESTATION.git
cd SBOM-ATTESTATION
```

## Project description

This work supports **trusted SBOM** practice for **C/C++** software: combine **Syft, Trivy, Distro2SBOM, CycloneDX-CLI, Hoppr, Grype**, and **repository-maintained application metadata** (JSON, CSV, or XML via `merge-sbom.ps1`) into **holistic CycloneDX** documents. **NTIA minimum elements** are checked with `check-ntia.ps1` and **Hoppr**. **Embedded signing** uses `scripts/sign-sbom.sh` (OpenSSL), with optional PKI hierarchy bootstrapping from `scripts/setup-pki.sh`. **GitHub Actions** and **GitLab CI** run the **same pipeline shape**: clean outputs → build → generate → enrich → validate → sign → scan → report → upload artifacts.

**Using your own C/C++ tree:** point the **local** script at `-SourcePath` and `-AppMetadataPath`, and set **CI** variables **`APP_DIR`** and **`APP_METADATA`** (see [CI/CD parity](#ci-cd-parity)). Replace the **build** step (`make -C $APP_DIR`) with your generator if you do not use Make.

**Avoiding stale reports:** every **CI** job and every **local** `generate-sbom.ps1` run (by default) **deletes prior root `sbom/*.json` and all `reports/*`** before regenerating, so you do not read yesterday’s Grype/Trivy output after a `git pull`. Use **`-NoClean`** only when you intentionally need to keep prior files. `sbom/pki/` is not removed by the clean step.

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
|   |-- app-metadata.json                # Custom component metadata (see also .csv / .xml)
|-- scripts/
|   |-- sign-sbom.sh                     # Canonicalize + sign + embed signature
|   |-- clean-sbom-outputs.sh            # CI/Linux: wipe generated sbom root JSON/tar + reports
|   `-- clean-sbom-outputs.ps1           # Windows: same (used by generate-sbom.ps1)
|-- sbom/                                # Generated SBOM outputs and PKI artifacts
|-- reports/                             # Validation, scan, and DB evidence outputs
|-- sbom_ui/
|   |-- app.py                           # Flask app: static Mission Control + REST APIs
|   |-- requirements.txt
|   `-- static/
|       `-- index.html                   # Mission Control UI (React via Babel in-page)
|-- viewer/                              # Standalone SBOM + Grype JSON viewer (static HTML/JS)
|-- generate-sbom.ps1                    # Local orchestrator (native/container mode)
|-- merge-sbom.ps1                       # Inject custom app metadata into SBOM
|-- check-ntia.ps1                       # NTIA minimum-elements check
|-- run-mission-control.ps1              # Quick start: Flask UI on $env:PORT (default 5000)
|-- start-ui-local.ps1                   # Picks a free port, prints URL, starts Flask
|-- Dockerfile                           # Container image for the UI/API (see also Procfile)
|-- Procfile                             # Process entry for compatible PaaS hosts
|-- render.yaml                          # Example Render service definition
|-- .github/workflows/sbom-pipeline.yml  # GitHub Actions pipeline
|-- .github/workflows/pages-ui.yml       # Optional: publish static UI to GitHub Pages
|-- .gitlab-ci.yml                       # GitLab CI pipeline
|-- FREE_HOSTING_SETUP.md                # Optional: Pages + remote API wiring (not required for local use)
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

### 1) Repo root and install UI dependencies

Use your local checkout as the working directory (this machine: `C:\Users\Soloman\sbom-attestation`):

```powershell
cd C:\Users\Soloman\sbom-attestation
python -m pip install -r .\sbom_ui\requirements.txt
```

If you do not have the repo yet, clone it and then `cd` to that folder (rename or clone into `C:\Users\Soloman\sbom-attestation` if you want the same layout).

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

By default, `generate-sbom.ps1` **cleans** existing pipeline outputs first (see [Project description](#project-description)). To keep previous `sbom/` JSON at the repo root and `reports/`, add **`-NoClean`**.

Example for a **non-default** app directory and metadata file:

```powershell
pwsh -ExecutionPolicy Bypass -File .\generate-sbom.ps1 -Mode native -SourcePath my-cpp-app -AppMetadataPath my-cpp-app/app-metadata.json
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

CI uploads these outputs in two bundles:

- `sbom-pipeline-essential`: the files Mission Control and most consumers need first (enriched SBOMs, public-key/signature evidence, validation summary, primary Grype/Trivy JSON, vulnerability summary, and build output)
- `sbom-pipeline-evidence`: the full `sbom/` + `reports/` evidence set for audit and troubleshooting

## Mission Control UI

The primary UI lives in `sbom_ui/static/index.html` (React loaded in-page). It talks to the Flask backend in `sbom_ui/app.py` for local generate/sign/scan, uploads, and GitHub/GitLab pipeline triggers.

**Start the app (recommended on Windows):**

```powershell
pwsh -ExecutionPolicy Bypass -File .\start-ui-local.ps1
```

The script chooses a free port (or `5000`/`$env:PORT` when set), binds `0.0.0.0`, and prints the URL. Alternatives:

```powershell
pwsh -ExecutionPolicy Bypass -File .\run-mission-control.ps1
# or
python .\sbom_ui\app.py
```

Open the URL shown in the terminal (typically `http://127.0.0.1:<port>/`).

**API base resolution (how the browser picks the backend):**

| Situation | Behavior |
|-----------|----------|
| `localhost` / `127.0.0.1` with the app origin | Uses **same origin** (no separate API URL). |
| Local hosts alias `www.sbomcontrol.com` or `sbomcontrol.com` **with a non-80/443 port** | Treated as local; uses **same origin**. |
| Query `?api=https://host` | Normalizes, saves to `localStorage` key `sbom_api_base`, uses that base. |
| `?reset_api=1` | Clears `sbom_api_base` (then reload). |
| GitHub Pages (`*.github.io`) or `sbomcontrol.com` **without** a saved override | Falls back to a **default public API** URL embedded in the page (change in Connect modal or `?api=`). |
| `file://` or missing origin | Defaults to `http://127.0.0.1:5000`. |

Use the **Connect** modal’s **API Base URL** field to point at any reachable backend; that value is persisted with the other connection settings.

**Optional local hostname:** add `127.0.0.1 www.sbomcontrol.com` to your hosts file, then open `http://www.sbomcontrol.com:<port>/` (match the port Flask prints). Remove or comment that line when you are not running the local server to avoid confusing browser errors.

**Standalone SBOM viewer:** the `viewer/` folder is a separate static page that loads a CycloneDX JSON file and a Grype JSON report from disk—useful for inspecting artifacts without the Mission Control backend.

**Optional remote hosting** (GitHub Pages static UI + API elsewhere) is documented in `FREE_HOSTING_SETUP.md` only if you need that deployment model; it is not required for local development.

### UI Provider Modes (GitHub + GitLab)

The UI supports both providers:

- GitHub Actions mode
- GitLab CI mode

Connect modal fields:

- Provider: `github` or `gitlab`
- Project path: `namespace/project`
- API Base URL: backend endpoint (local: same origin; remote: `https://your-api-host`)
- Access token: optional for public read; required for trigger unless backend env tokens are configured

Mission Control behavior implemented:

- GitHub and GitLab pipeline trigger from the same UI (`Pipelines -> Launch`)
- GitHub job log view with backend token fallback
- GitLab multi-stage pipelines (`Build -> Generate -> Validate -> Sign -> Scan -> Report`) with artifact handoff between jobs
- Saved API base override via `?api=...` and Connect modal `API Base URL`

Recommended backend env vars (remote API host):

- `GITHUB_TOKEN` for GitHub trigger/read/log flows
- `GITLAB_TOKEN` for GitLab trigger/read flows
- Optional: `GITLAB_TRIGGER_TOKEN` for GitLab trigger-token mode

## CI/CD parity

Both pipelines **clean** generated outputs at the start (`scripts/clean-sbom-outputs.sh`), then build, generate SBOMs, merge metadata, validate, sign, scan, and publish artifacts.

### GitHub

Workflow: `.github/workflows/sbom-pipeline.yml`

| Variable / secret | Purpose |
|---|---|
| `APP_DIR` | Directory of your C/C++ project (default `example-app`). Must contain the build used in the workflow (`make -C $APP_DIR`). |
| `APP_METADATA` | Path passed to `merge-sbom.ps1` (default `example-app/app-metadata.json`). Use `.json`, `.csv`, or `.xml`. |
| `SBOM_PRIVATE_KEY_PEM` | Optional secret: PEM for signing in CI. |

### GitLab

Workflow: `.gitlab-ci.yml`

| Variable | Purpose |
|---|---|
| `APP_DIR` | Same as GitHub (default `example-app`). |
| `APP_METADATA` | Same as GitHub; keep it consistent when you change `APP_DIR`. |

Stages (both providers):

- Build
- Generate
- Validate
- Sign
- Scan
- Report

### Local GitLab CI emulation

Use the helper script to preview or execute the same stage flow locally:

```bash
# Print stage commands only (no execution)
make ci-local-dry-run

# One-command smoke execution
make ci-local-smoke

# Fuller local execution path
make ci-local-full
```

Helper script:

- `scripts/gitlab-ci-local-dry-run.sh --dry-run`
- `scripts/gitlab-ci-local-dry-run.sh --smoke`
- `scripts/gitlab-ci-local-dry-run.sh --full`

PowerShell wrapper:

- `pwsh -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode dry-run`
- `pwsh -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode smoke`
- `pwsh -ExecutionPolicy Bypass -File .\scripts\gitlab-ci-local-dry-run.ps1 -Mode full`

Optional Make aliases for PowerShell:

- `make ci-local-dry-run-ps`
- `make ci-local-smoke-ps`
- `make ci-local-full-ps`

## Current Implementation Status

The following is implemented and validated in this repository:

- **SBOM generation:** Syft + Trivy + Distro2SBOM are merged via CycloneDX for source/build targets.
- **Metadata enrichment:** Custom C/C++ application component metadata is merged into generated SBOMs.
- **Validation:** CycloneDX schema checks, local NTIA checks, and Hoppr NTIA validation are in place.
- **Attestation:** Embedded SBOM signature generation + verification is implemented via OpenSSL-based flow.
- **Vulnerability analysis:** Grype and Trivy scans produce JSON/table outputs and combined summary evidence.
- **Mission Control UI:** Flask-served UI plus APIs support GitHub and GitLab pipeline trigger/monitor flow; optional static hosting is described in `FREE_HOSTING_SETUP.md`.
- **Security hardening applied:** CI supports `SBOM_PRIVATE_KEY_PEM` secret injection and excludes private key material from CI artifact upload.

## Real-World Threat Relevance

Recent Trivy supply-chain incident reporting highlights an important point: security tooling is itself part of the software supply chain and can be targeted.

- Aqua incident advisory and remediation updates: [Aqua Security Trivy update](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- Example downstream impact reporting: [BleepingComputer coverage](https://www.bleepingcomputer.com/news/security/cisco-source-code-stolen-in-trivy-linked-dev-environment-breach/)

Controls reflected in this repository after those lessons:

- Avoid mutable scanner references in CI where possible; prefer pinned versions.
- Treat CI credentials/tokens as high-risk secrets and use least privilege.
- Keep signing key material out of artifacts; inject secrets via CI protected variables.
- Preserve auditable evidence (validation logs, scan outputs, DB status) for incident response and attestation.

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

CI now publishes these as two downloadable bundles:

- `essential`: quick-consumption bundle for scanners, UI flows, and reviewer handoff
- `evidence`: full audit bundle with raw logs, DB freshness artifacts, validation logs, and supporting reports

## How to adapt this for another C/C++ project

1. Copy or replace `example-app/` with your tree (or point **`APP_DIR`** / **`-SourcePath`** at it).
2. Edit metadata (**`app-metadata.json`**, or **`.csv`** / **`.xml`** with the same fields) for supplier, application identity, and optional **`custom_components`** (multi-component dependency graph).
3. In **`.github/workflows/sbom-pipeline.yml`**, set **`APP_DIR`** and **`APP_METADATA`** to match your paths.
4. In **`.gitlab-ci.yml`**, set the same **`APP_DIR`** and **`APP_METADATA`** variables.
5. Change the **build** step if you do not use Make (for example invoke CMake or Ninja instead of `make -C $APP_DIR`).
6. Locally, use **`generate-sbom.ps1`** with **`-SourcePath`**, **`-AppMetadataPath`**, and optionally **`-SbomDir`** / **`-ReportDir`** if you keep outputs elsewhere.
7. Keep default SBOM **file names** under `sbom/` and `reports/` stable if you rely on Mission Control or other automation.
8. Run **`generate-sbom.ps1`** after **`git pull`** (clean runs by default) so local results match what CI would produce; use **`-NoClean`** only when debugging.

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

## Security Notes

- Never commit private signing keys
- In CI, prefer injecting `SBOM_PRIVATE_KEY_PEM` as a protected secret variable instead of generating a new private key in artifacts
- Keep branch protections enabled for production branches
- Use least-privilege tokens for pipeline triggers
- Treat generated vulnerability reports as sensitive operational data

## Data Usage and Management Plan (Current Pipeline)

All SBOM outputs are treated as sensitive software supply-chain records. The following reflects the repository's current behavior and CI configuration.

- **Source code authority:** GitHub (`Richmansolom/SBOM-ATTESTATION`) is the primary maintained source. GitLab is kept aligned through sync updates (direct push when allowed, or protected-branch merge request flow).
- **SBOM artifacts:** SBOM files under `sbom/` are published as CI artifacts in both GitHub Actions and GitLab CI.
- **Artifact retention:** Current retention is **7 days** (GitHub `retention-days: 7`, GitLab `expire_in: 1 week`), not three months.
- **Vulnerability reports:** Grype and Trivy outputs are archived in `reports/` (JSON and table/text outputs, plus `vulnerability-analysis.txt`, and DB status/update/provider evidence). HTML vulnerability reports are not currently produced by default.
- **Cryptographic keys:** `scripts/sign-sbom.sh` can generate an RSA keypair in `sbom/pki/` at runtime when no key is provided. CI pipelines support secret-based key injection via `SBOM_PRIVATE_KEY_PEM`, and private key artifact upload is explicitly excluded.
- **Credentials and tokens:** The UI stores connection config in browser `sessionStorage` (`sbom_cfg`). If provided, tokens are sent only to this backend via `X-SBOM-TOKEN` for provider API calls. Tokens are optional for public read operations and are typically required for protected trigger operations.
- **External data flows:** SBOM processing/scanning is executed locally in runner containers. The pipeline does pull vulnerability databases and container images from upstream registries (for example, Grype DB and Trivy DB sources).
- **PII handling:** The pipeline and UI are designed for software/component metadata and do not intentionally collect or process personally identifiable information (PII).

## License

MIT
