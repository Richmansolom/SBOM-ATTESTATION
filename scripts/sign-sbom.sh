#!/bin/bash
# Sign SBOM with embedded CycloneDX 1.6 signature (RS384, RSA 3072)
# Per: PKI approach, CNSA 2.0-aligned, signature embedded in SBOM

set -e

INPUT_SBOM="$1"
OUTPUT_SBOM="$2"
KEY_DIR="${3:-pki}"
ALG="RS384"

if [ -z "$INPUT_SBOM" ] || [ -z "$OUTPUT_SBOM" ]; then
  echo "Usage: $0 <input-sbom.json> <output-signed-sbom.json> [key-dir]"
  exit 1
fi

mkdir -p "$KEY_DIR"
PRIV_KEY="$KEY_DIR/sbom_private_key.pem"
PUB_KEY="$KEY_DIR/sbom_public_key.pem"

# Generate RSA 3072 key pair (CNSA 2.0 aligned)
# CI: unencrypted for compatibility. Production: use -aes256 and secure passphrase.
if [ ! -f "$PRIV_KEY" ]; then
  echo "==> Generating RSA 3072-bit key pair (CNSA 2.0)"
  openssl genrsa -out "$PRIV_KEY" 3072
  openssl rsa -in "$PRIV_KEY" -pubout -out "$PUB_KEY"
fi

# Canonical JSON: BOM without signature (for signing)
# Sign the exact bytes - must match on verify
SBOM_NO_SIG=$(jq -c -S 'del(.signature)' "$INPUT_SBOM")
TMP_CANONICAL=$(mktemp)
echo -n "$SBOM_NO_SIG" > "$TMP_CANONICAL"

# Sign with SHA-384 (CNSA 2.0)
SIG_BIN=$(mktemp)
openssl dgst -sha384 -sign "$PRIV_KEY" -out "$SIG_BIN" "$TMP_CANONICAL"
SIG_B64=$(base64 < "$SIG_BIN" | tr -d '\n')
rm -f "$TMP_CANONICAL" "$SIG_BIN"

# Extract JWK (n, e) from public key
# Modulus hex -> base64url | Exponent 65537 -> AQAB
MOD_HEX=$(openssl rsa -pubin -in "$PUB_KEY" -noout -modulus | sed 's/Modulus=//')
# Ensure even length
[ $(echo -n "$MOD_HEX" | wc -c) -eq 0 ] && MOD_HEX="0"
if [ $(($(echo -n "$MOD_HEX" | wc -c) % 2)) -eq 1 ]; then
  MOD_HEX="0$MOD_HEX"
fi
N_B64URL=$(python3 -c "
import base64, binascii
h='$MOD_HEX'
b=binascii.unhexlify(h)
print(base64.urlsafe_b64encode(b).decode().rstrip('='))
")

# Add signature to SBOM (CycloneDX 1.6 format - see authenticity-verification)
# Ensure specVersion supports signature object
jq --arg alg "$ALG" \
   --arg n "$N_B64URL" \
   --arg val "$SIG_B64" \
   '(.specVersion = (.specVersion // "1.4" | if . < "1.6" then "1.6" else . end)) | . + {"signature": {"algorithm": $alg, "publicKey": {"kty": "RSA", "n": $n, "e": "AQAB"}, "value": $val}}' \
   "$INPUT_SBOM" > "$OUTPUT_SBOM"

echo "==> Signed SBOM written to $OUTPUT_SBOM (algorithm: $ALG)"

# Verify: extract canonical, verify signature
echo "==> Verifying embedded signature..."
VERIFY_CANONICAL=$(mktemp)
SIG_FOR_VERIFY=$(mktemp)
jq -c -S 'del(.signature)' "$OUTPUT_SBOM" > "$VERIFY_CANONICAL"
echo "$SIG_B64" | base64 -d > "$SIG_FOR_VERIFY" 2>/dev/null || echo "$SIG_B64" | base64 -D > "$SIG_FOR_VERIFY"
openssl dgst -sha384 -verify "$PUB_KEY" -signature "$SIG_FOR_VERIFY" "$VERIFY_CANONICAL" || {
  rm -f "$VERIFY_CANONICAL" "$SIG_FOR_VERIFY"
  echo "ERROR: Signature verification failed"
  exit 1
}
rm -f "$VERIFY_CANONICAL" "$SIG_FOR_VERIFY"
echo "==> Signature verification passed"
