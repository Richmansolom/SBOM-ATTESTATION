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
if [ ! -f "$PRIV_KEY" ]; then
  echo "==> Generating RSA 3072-bit key pair (CNSA 2.0)"
  openssl genrsa -out "$PRIV_KEY" 3072
  openssl rsa -in "$PRIV_KEY" -pubout -out "$PUB_KEY"
fi

# Canonical JSON: BOM without signature - write directly (no variable/newline issues)
TMP_CANONICAL=$(mktemp)
jq -c -S 'del(.signature)' "$INPUT_SBOM" > "$TMP_CANONICAL"

# Sign with SHA-384 (CNSA 2.0)
SIG_BIN=$(mktemp)
openssl dgst -sha384 -sign "$PRIV_KEY" -out "$SIG_BIN" "$TMP_CANONICAL"
SIG_B64=$(base64 < "$SIG_BIN" | tr -d '\n\r')
rm -f "$SIG_BIN"

# Extract JWK (n, e) from public key - use file to avoid CLI length limits
MOD_HEX=$(openssl rsa -pubin -in "$PUB_KEY" -noout -modulus 2>/dev/null | sed 's/Modulus=//' | tr -d '\n\r')
[ -z "$MOD_HEX" ] && MOD_HEX="0"
len=${#MOD_HEX}
if [ $((len % 2)) -eq 1 ]; then
  MOD_HEX="0$MOD_HEX"
fi

MOD_FILE=$(mktemp)
echo -n "$MOD_HEX" > "$MOD_FILE"
N_B64URL=$(python3 -c "
import base64, binascii
with open('$MOD_FILE') as f:
    h = f.read().strip()
b = binascii.unhexlify(h)
print(base64.urlsafe_b64encode(b).decode().rstrip('='))
")
rm -f "$MOD_FILE"

# Add signature to SBOM - use CANONICAL as base so verify gets same bytes we signed
jq --arg alg "$ALG" \
   --arg n "$N_B64URL" \
   --arg val "$SIG_B64" \
   '. + {"signature": {"algorithm": $alg, "publicKey": {"kty": "RSA", "n": $n, "e": "AQAB"}, "value": $val}}' \
   "$TMP_CANONICAL" > "$OUTPUT_SBOM"

echo "==> Signed SBOM written to $OUTPUT_SBOM (algorithm: $ALG)"

# Verify - use same TMP_CANONICAL we signed (guaranteed byte match)
echo "==> Verifying embedded signature..."
SIG_FOR_VERIFY=$(mktemp)
printf '%s' "$SIG_B64" | base64 -d > "$SIG_FOR_VERIFY" 2>/dev/null || printf '%s' "$SIG_B64" | base64 -D > "$SIG_FOR_VERIFY" 2>/dev/null || true
if [ ! -s "$SIG_FOR_VERIFY" ]; then
  printf '%s' "$SIG_B64" | python3 -c "import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))" > "$SIG_FOR_VERIFY"
fi
if ! openssl dgst -sha384 -verify "$PUB_KEY" -signature "$SIG_FOR_VERIFY" "$TMP_CANONICAL"; then
  rm -f "$TMP_CANONICAL" "$SIG_FOR_VERIFY"
  echo "ERROR: Signature verification failed"
  exit 1
fi
rm -f "$TMP_CANONICAL" "$SIG_FOR_VERIFY"
echo "==> Signature verification passed"
