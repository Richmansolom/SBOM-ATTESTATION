# Key Distribution Infrastructure for SBOM Attestation

This directory holds the PKI setup for global attestation of signed SBOMs.

## Approach

Per the requirement: *"Create a key distribution infrastructure to enable global attestation of signed SBOMs... PKI which can be implemented using OpenSSL."*

### Current Implementation (Proof of Concept)

- **RSA 3072-bit** keys (CNSA 2.0/1.0 aligned)
- **RS384** (RSA-SHA384) signatures
- **Embedded signature** in SBOM (CycloneDX 1.6 JSON format)
- Keys generated with: `openssl genrsa -aes256 -out sbom_private_key.pem 3072 -passout pass:""`
- Public key extracted: `openssl rsa -in sbom_private_key.pem -pubout -out sbom_public_key.pem`

Blank passphrase for CI/testing. **For production**: use a strong passphrase or HSM.

### Production: Root CA (Chain of Trust)

For full PKI, use a trusted root CA ([chain of trust](https://en.wikipedia.org/wiki/Root_certificate)):

1. Create self-signed root CA
2. Issue application-specific certs signed by root
3. Distribute root CA public key for verification
4. Each app SBOM signed with its own cert

Example (simplified):
```bash
# Root CA
openssl req -x509 -sha384 -days 1825 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt -nodes -subj "/CN=SBOM-Root-CA"

# App cert (signed by root)
openssl req -new -newkey rsa:3072 -keyout app.key -out app.csr -nodes -subj "/CN=sbom-attestation"
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in app.csr -out app.crt -days 365 -sha384 -CAcreateserial
```

## Key Protection

- **Private keys**: Never commit to repo. CI generates ephemeral keys per run.
- **Public keys**: Distributed with SBOM; recipients use for verification.
- Algorithms/strengths: CNSA 2.0 (RSA 3072, SHA-384).

## CycloneDX Signature Format

Signatures are embedded per [CycloneDX Authenticity Verification](https://cyclonedx.org/use-cases/authenticity-verification/):

```json
{
  "signature": {
    "algorithm": "RS384",
    "publicKey": {"kty": "RSA", "n": "<base64url>", "e": "AQAB"},
    "value": "<base64 signature>"
  }
}
```

Signed payload: canonical JSON of BOM *without* the signature object.

## Validation

- **CycloneDX-CLI**: Validates schema (including signature object)
- **Hoppr**: Can validate SBOM structure
- **Manual (OpenSSL)**: Remove signature from JSON, canonicalize, verify:
  ```bash
  jq -c -S 'del(.signature)' signed-sbom.json > canonical.json
  openssl dgst -sha384 -verify sbom_public_key.pem -signature sig.bin canonical.json
  ```
