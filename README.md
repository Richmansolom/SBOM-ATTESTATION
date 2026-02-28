# Software Bill of Materials (SBOM) Attestation

**Company:** Lockheed Martin Corporation  
**Context:** CISA open source SBOM initiative

## Overview

This project provides an SBOM generator and attestation pipeline for custom C/C++ applications. It combines existing COTS SBOM tools (Syft, CycloneDX-CLI, Hoppr, Grype) with custom metadata and signing to produce trusted SBOMs that meet NTIA Minimum Elements.

## Features

- **Custom app + COTS components:** Captures both your application and its dependencies in a single SBOM
- **Native and container support:** Scan source directories or Docker/Podman images
- **NTIA validation:** SBOMs validated against NTIA Minimum Elements (local script + Hoppr)
- **SBOM signing & verification:** OpenSSL RSA signatures for attestation
- **Vulnerability scanning:** Grype for SBOM-based vulnerability detection
- **Custom metadata:** JSON-based app metadata (easy to maintain in repo)

## Example C++ Application

The `example-app/` directory contains a minimal C++ application with:

- **4 custom components:** `io`, `engine`, `math`, `util`
- **2+ dependency levels:** `main → io/printer → engine/compute → (math/series, util/string_util)`

This satisfies the requirement for "at least three custom components and at least two levels of custom component dependency."

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

### Generate SBOM locally (Docker)

```bash
# From project root
docker run --rm -v "${PWD}:/src" anchore/syft:latest dir:/src/example-app -o cyclonedx-json > sbom/sbom-source.json

# Enrich with metadata
pwsh ./merge-sbom.ps1 -InputSbom sbom/sbom-source.json -AppMetadata example-app/app-metadata.json -OutputSbom sbom/sbom-source.enriched.json

# NTIA check
pwsh ./check-ntia.ps1 -SbomFile sbom/sbom-source.enriched.json
```

### Container mode

```bash
cd example-app
docker build -t sbom-demo-app:1.0 .
docker run --rm sbom-demo-app:1.0
```

## COTS Tools Used

| Tool           | Purpose                          |
|----------------|----------------------------------|
| Syft           | SBOM generation (CycloneDX)      |
| CycloneDX-CLI  | SBOM structure validation        |
| Hoppr          | NTIA Minimum Elements validation|
| Grype          | SBOM vulnerability scanning     |
| OpenSSL        | SBOM signing and verification   |

## Custom Metadata Format

`example-app/app-metadata.json` defines the custom application component. It uses JSON for ease of maintenance in the source repository. Alternative formats (CSV, XML, lockfile) could be supported by adapting `merge-sbom.ps1`.

## License

MIT
