# PKI Key Distribution for SBOM Attestation

This directory implements a practical PKI model for globally verifiable SBOM signatures.

## Security Profile

- Signature algorithm: `RS384` (`RSA-3072` + `SHA-384`)
- Baseline: CNSA 1.0 compatible profile (widely available in OpenSSL today)
- CNSA 2.0 readiness: keep SHA-384 canonicalization and certificate chain distribution in place so a future PQ/hybrid signer can replace leaf keys without redesigning the pipeline

## What is provided

- `scripts/setup-pki.sh`: generates an offline root CA, an intermediate CA, and a leaf SBOM signer cert/key
- `scripts/sign-sbom.sh`: embeds CycloneDX signature directly in SBOM JSON
- GitLab CI support for key injection via `SBOM_PRIVATE_KEY_PEM` (recommended for protected runners)

## Global attestation model

1. Keep `root-ca.key.pem` offline.
2. Publish `root-ca.cert.pem` and `intermediate-ca.cert.pem` through your enterprise trust distribution channel.
3. Use `sbom-signer.key.pem` only on controlled signing infrastructure.
4. Verify chain + signature:
   - trust root/intermediate certs
   - validate SBOM schema (`cyclonedx-cli`)
   - validate NTIA profile (`hoppr`)
   - verify cryptographic signature (`openssl`)

## Generate PKI hierarchy

```bash
bash scripts/setup-pki.sh sbom/pki
```

Generated files:

- `root-ca.key.pem`, `root-ca.cert.pem`
- `intermediate-ca.key.pem`, `intermediate-ca.cert.pem`
- `sbom-signer.key.pem`, `sbom-signer.cert.pem`
- `ca-chain.cert.pem` (intermediate + root)
- `sbom_public_key.pem` (for CycloneDX embedded signature verification)

## Key protection requirements

- Never commit private keys.
- Protect root and intermediate private keys with passphrases and offline storage.
- Use CI secret variables or HSM-backed signing where available.
- Rotate leaf signing certificates regularly and revoke on compromise.

## Signature validation sequence

1. CycloneDX schema validation:
   - `cyclonedx-cli validate --input-file sbom/sbom-source.enriched.json`
2. NTIA minimum elements:
   - `hopctl validate sbom --sbom sbom/sbom-source.enriched.json --profile ntia`
3. Cryptographic verification:
   - canonicalize payload by removing `.signature`
   - verify with `openssl dgst -sha384 -verify sbom/pki/sbom_public_key.pem ...`
