# Software Bill of Materials (SBOM) Attestation

**Company:** Lockheed Martin Corporation  
**Context:** CISA open source SBOM initiative

## Overview

This project provides an SBOM generator and attestation pipeline for custom C/C++ applications. It combines existing COTS SBOM tools (Syft, Trivy, Distro2SBOM, CycloneDX-CLI, Hoppr, Grype) with custom metadata and signing to produce trusted SBOMs that meet NTIA Minimum Elements.

## Features

- **Custom app + COTS components:** Captures both your application and its dependencies in a single SBOM
- **Native and container support:** `generate-sbom.ps1 -Mode native` (directory) or `-Mode container` (Docker/Podman image)
- **NTIA Minimum Elements:** Validated via `check-ntia.ps1` and **Hoppr** (`--profile ntia`)
- **NTIA validation:** SBOMs validated against NTIA Minimum Elements (local script + Hoppr)
- **SBOM signing & verification:** OpenSSL RSA signatures for attestation
- **Vulnerability scanning:** Grype for SBOM-based vulnerability detection
- **Custom metadata:** JSON-based app metadata (easy to maintain in repo)

## Example C++ Application

The `example-app/` directory contains a minimal C++ application used to demonstrate the pipeline. This repository intentionally uses the example app as the target implementation (not University-Management-System), while keeping the same SBOM attestation architecture and controls.

**This SBOM infrastructure is for any software** — replace `example-app/` with your own project and update `app-metadata.json`. The example satisfies pipeline requirements: >=3 custom components, >=2 dependency levels.

## Project Structure

```
sbom-attestation/
├── example-app/           # Example C++ application
│   ├── src/
│   ├── include/
│   ├── Makefile
│   ├── Dockerfile
│   └── app-metadata.json  # Custom app dependency metadata (JSON)
├── merge-sbom.ps1         # Enriches SBOM with app metadata
├── check-ntia.ps1         # NTIA Minimum Elements validator
├── .gitlab-ci.yml         # GitLab CI/CD pipeline
└── README.md
```

## GitHub Actions Pipeline

The workflow (`.github/workflows/sbom-pipeline.yml`) runs on push to `main`/`master` and performs the same steps as the GitLab pipeline. Artifacts are available under the workflow run (Summary → Artifacts).

## GitLab CI/CD Pipeline

The pipeline (`.gitlab-ci.yml`) performs the same steps when using GitLab:

1. **Build** the example C++ application
2. **Generate SBOMs** (source and build outputs) with Syft (CycloneDX format)
3. **Enrich SBOMs** with custom app metadata via `merge-sbom.ps1`
4. **Sign and validate** SBOMs using OpenSSL RSA signatures
5. **Validate** SBOM structure (CycloneDX-CLI) and NTIA elements (check-ntia.ps1, Hoppr)
6. **Vulnerability scan** with Grype
7. **Produce** vulnerability analysis report

**Artifacts** (available after each run):

- `example-app/build/` — compiled binary and build output
- `sbom/` — raw SBOMs, enriched SBOMs, signatures
- `reports/` — build log, Grype report, vulnerability analysis, NTIA summary, signature checks

## Local Usage

### Prerequisites

- Docker or Podman
- PowerShell 7+ (for scripts)
- GNU Make (to build the app)

### Build the app

```bash
cd example-app
make
./build/sbom_demo_app
```

### Generate SBOM locally (PowerShell)

Requires: Docker Desktop (or Podman), PowerShell 7+

**Native mode** (scan `example-app/` directory):

```powershell
cd C:\path\to\sbom-attestation
pwsh -ExecutionPolicy Bypass -File ./generate-sbom.ps1 -Mode native
```

**Container mode** (build Docker image, then scan):

```powershell
cd C:\path\to\sbom-attestation
pwsh -ExecutionPolicy Bypass -File ./generate-sbom.ps1 -Mode container
```

**With Podman instead of Docker:**

```powershell
pwsh -ExecutionPolicy Bypass -File ./generate-sbom.ps1 -Mode native -ContainerRuntime podman
```

Outputs: `sbom/`, `reports/` (includes NTIA summary, Hoppr log).

### SBOM Generator UI (Flask)

Run the backend-driven UI that supports `generate -> sign -> scan` actions:

```powershell
cd C:\path\to\sbom-attestation
python -m pip install -r .\sbom_ui\requirements.txt
python .\sbom_ui\app.py
```

Then open:

- `http://127.0.0.1:5000`

Notes:
- This UI targets the example C++ application in `example-app/`.
- It uses Dockerized tools under the hood for signing/scanning endpoints.

### Container mode

```bash
cd example-app
docker build -t sbom-demo-app:1.0 .
docker run --rm sbom-demo-app:1.0
```

## Key Distribution Infrastructure (PKI)

Per the attestation requirement, this project implements a PKI for signed SBOMs:

- **RSA 3072-bit** keys (CNSA 2.0 aligned)
- **RS384** (RSA-SHA384) signatures embedded in SBOM (CycloneDX 1.6)
- **Script**: `scripts/sign-sbom.sh` — generates keys, signs canonical JSON, embeds signature
- **Public key** distributed with SBOM (in `signature.publicKey`) and artifacts (`sbom/pki/sbom_public_key.pem`)

For production PKI with root CA chain of trust, see `pki/README.md`. Manual verification: remove `signature` from JSON, canonicalize, then `openssl dgst -sha384 -verify pubkey.pem -signature sig.bin canonical.json`.

## COTS Tools Used

| Tool           | Purpose                          |
|----------------|----------------------------------|
| Syft           | Component/package SBOM generation (CycloneDX) |
| Trivy          | Filesystem SBOM generation (CycloneDX) |
| Distro2SBOM    | Distro/package manager SBOM generation |
| CycloneDX-CLI  | SBOM structure validation        |
| Hoppr          | NTIA Minimum Elements validation |
| Grype          | SBOM vulnerability scanning     |
| OpenSSL        | Key generation and signing       |

## Using for Your Software

This SBOM pipeline is **not tied to the example app**. To use it for your own software:

1. Point the pipeline at your app path (update `APP_DIR` in CI or pass your path to Syft/merge-sbom)
2. Create `app-metadata.json` for your application (name, version, supplier, etc.)
3. Ensure your C/C++ project has ≥3 custom components and ≥2 dependency levels if that requirement applies

The same pipeline, scripts, and PKI work for any software.

## Custom Metadata Format

`app-metadata.json` defines the custom application component. It uses JSON for ease of maintenance. Alternative formats (CSV, XML, lockfile) could be supported by adapting `merge-sbom.ps1`.

## License

MIT
