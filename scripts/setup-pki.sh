#!/usr/bin/env bash
set -euo pipefail

# Build a simple 3-tier PKI for global SBOM signature attestation:
# offline root CA -> intermediate CA -> SBOM signer cert.

OUT_DIR="${1:-sbom/pki}"
mkdir -p "$OUT_DIR"

ROOT_KEY="$OUT_DIR/root-ca.key.pem"
ROOT_CERT="$OUT_DIR/root-ca.cert.pem"
INT_KEY="$OUT_DIR/intermediate-ca.key.pem"
INT_CSR="$OUT_DIR/intermediate-ca.csr.pem"
INT_CERT="$OUT_DIR/intermediate-ca.cert.pem"
LEAF_KEY="$OUT_DIR/sbom-signer.key.pem"
LEAF_CSR="$OUT_DIR/sbom-signer.csr.pem"
LEAF_CERT="$OUT_DIR/sbom-signer.cert.pem"
CHAIN_CERT="$OUT_DIR/ca-chain.cert.pem"
PUB_KEY="$OUT_DIR/sbom_public_key.pem"

echo "==> Creating PKI hierarchy in: $OUT_DIR"

# Root CA: RSA-4096 + SHA-384 for durable anchor.
openssl req -x509 -newkey rsa:4096 -sha384 -days 3650 -nodes \
  -subj "/CN=SBOM Root CA/O=SBOM Attestation/OU=Offline Root" \
  -keyout "$ROOT_KEY" -out "$ROOT_CERT"

# Intermediate CA: RSA-3072 + SHA-384.
openssl req -new -newkey rsa:3072 -sha384 -nodes \
  -subj "/CN=SBOM Intermediate CA/O=SBOM Attestation/OU=Issuing CA" \
  -keyout "$INT_KEY" -out "$INT_CSR"

openssl x509 -req -in "$INT_CSR" -CA "$ROOT_CERT" -CAkey "$ROOT_KEY" \
  -CAcreateserial -out "$INT_CERT" -days 1825 -sha384 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer")

# Leaf SBOM signer: RSA-3072 + SHA-384.
openssl req -new -newkey rsa:3072 -sha384 -nodes \
  -subj "/CN=SBOM Signing Certificate/O=SBOM Attestation/OU=CI Signer" \
  -keyout "$LEAF_KEY" -out "$LEAF_CSR"

openssl x509 -req -in "$LEAF_CSR" -CA "$INT_CERT" -CAkey "$INT_KEY" \
  -CAcreateserial -out "$LEAF_CERT" -days 365 -sha384 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer")

cat "$INT_CERT" "$ROOT_CERT" > "$CHAIN_CERT"
openssl rsa -in "$LEAF_KEY" -pubout -out "$PUB_KEY"

echo "==> PKI generated:"
echo "    Root cert:          $ROOT_CERT"
echo "    Intermediate cert:  $INT_CERT"
echo "    Leaf signer cert:   $LEAF_CERT"
echo "    CA chain bundle:    $CHAIN_CERT"
echo "    SBOM public key:    $PUB_KEY"
echo ""
echo "IMPORTANT: keep '$ROOT_KEY' and '$INT_KEY' offline and protected."
