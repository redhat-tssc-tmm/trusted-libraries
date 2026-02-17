#!/bin/bash
#
# Attestation Signature Verification Script
#
# This script fetches an attestation from the Red Hat Trusted Libraries index
# and attempts to verify its signature using cosign.
#
# Usage:
#   ./verify_attestation.sh <public_key_file>
#
# Example:
#   ./verify_attestation.sh ../redhat-release3.pub
#

set -e

# Configuration
PACKAGE="typer"
VERSION="0.21.2"
FILENAME="typer-0.21.2-0-py3-none-any.whl"

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <public_key_file>"
    echo "Example: $0 ../redhat-release3.pub"
    exit 1
fi

PUBLIC_KEY_FILE="$1"

if [ ! -f "$PUBLIC_KEY_FILE" ]; then
    echo "Error: Public key file not found: $PUBLIC_KEY_FILE"
    exit 1
fi

# Check for required tools
command -v cosign >/dev/null 2>&1 || { echo "Error: cosign is required but not installed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed."; exit 1; }

echo "============================================================"
echo "Attestation Signature Verification"
echo "============================================================"
echo ""
echo "Package:    ${PACKAGE}"
echo "Version:    ${VERSION}"
echo "Filename:   ${FILENAME}"
echo "Public Key: ${PUBLIC_KEY_FILE}"
echo ""

# Step 1: Get index URL from pip config
echo "[1/6] Getting index URL from pip config..."
INDEX_URL=$(pip config get global.index-url)
INDEX_URL="${INDEX_URL%/}/"  # Ensure trailing slash

# Extract base URL with credentials
BASE_WITH_CREDS=$(python3 -c "
from urllib.parse import urlparse
url = '''${INDEX_URL}'''
parsed = urlparse(url)
print(f'{parsed.scheme}://{parsed.username}:{parsed.password}@{parsed.hostname}')
")

echo "       Index URL configured: OK"

# Step 2: Fetch the attestation
echo ""
echo "[2/6] Fetching attestation from integrity API..."
ATTESTATION_URL="${BASE_WITH_CREDS}/api/pypi/trusted-libraries/main/integrity/${PACKAGE}/${VERSION}/${FILENAME}/provenance/"

ATTESTATION_FILE=$(mktemp /tmp/attestation.XXXXXX.json)
HTTP_CODE=$(curl -s -w "%{http_code}" -o "$ATTESTATION_FILE" "$ATTESTATION_URL")

if [ "$HTTP_CODE" != "200" ]; then
    echo "       Error: Failed to fetch attestation (HTTP $HTTP_CODE)"
    cat "$ATTESTATION_FILE"
    rm -f "$ATTESTATION_FILE"
    exit 1
fi

echo "       Attestation fetched: OK"

# Step 3: Extract statement and signature
echo ""
echo "[3/6] Extracting statement and signature..."

STATEMENT_B64_FILE=$(mktemp /tmp/statement.XXXXXX.b64)
STATEMENT_JSON_FILE=$(mktemp /tmp/statement.XXXXXX.json)
SIGNATURE_B64_FILE=$(mktemp /tmp/signature.XXXXXX.b64)

jq -r '.attestation_bundles[0].attestations[0].envelope.statement' "$ATTESTATION_FILE" > "$STATEMENT_B64_FILE"
jq -r '.attestation_bundles[0].attestations[0].envelope.signature' "$ATTESTATION_FILE" > "$SIGNATURE_B64_FILE"

# Decode statement for display
base64 -d "$STATEMENT_B64_FILE" > "$STATEMENT_JSON_FILE"

echo "       Statement extracted: OK"
echo "       Signature extracted: OK"

# Step 4: Display attestation details
echo ""
echo "[4/6] Attestation details:"
echo ""
echo "       Subject: $(jq -r '.subject[0].name' "$STATEMENT_JSON_FILE")"
echo "       SHA256:  $(jq -r '.subject[0].digest.sha256' "$STATEMENT_JSON_FILE")"
echo "       Builder: $(jq -r '.predicate.predicate.builder.id' "$STATEMENT_JSON_FILE")"
echo "       Built:   $(jq -r '.predicate.predicate.metadata.buildFinishedOn' "$STATEMENT_JSON_FILE")"
echo ""

SIGNATURE=$(cat "$SIGNATURE_B64_FILE")
SIG_DECODED_LEN=$(base64 -d "$SIGNATURE_B64_FILE" | wc -c)
echo "       Signature (base64, first 60 chars): ${SIGNATURE:0:60}..."
echo "       Signature decoded length: ${SIG_DECODED_LEN} bytes"

echo ""
echo "--- Full Attestation (raw from API) ---"
jq . "$ATTESTATION_FILE"

echo ""
echo "--- Decoded Statement ---"
jq . "$STATEMENT_JSON_FILE"

# Step 5: Clean the public key (remove any extra lines before PEM header)
echo ""
echo "[5/6] Preparing public key..."

CLEAN_KEY_FILE=$(mktemp /tmp/clean-key.XXXXXX.pub)
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$PUBLIC_KEY_FILE" > "$CLEAN_KEY_FILE"

if [ ! -s "$CLEAN_KEY_FILE" ]; then
    echo "       Error: Could not extract PEM public key from $PUBLIC_KEY_FILE"
    exit 1
fi

# Detect key type
KEY_INFO=$(openssl pkey -pubin -in "$CLEAN_KEY_FILE" -text -noout 2>/dev/null | head -1)
echo "       Key type: $KEY_INFO"

# Step 6: Verify signature with cosign
echo ""
echo "[6/6] Verifying signature with cosign..."
echo ""
echo "       Attempting verification with base64-encoded statement..."
echo "       Command: cosign verify-blob --key $PUBLIC_KEY_FILE --signature <sig.b64> --insecure-ignore-tlog=true <statement.b64>"
echo ""

# Try verification
set +e  # Don't exit on error for this section

# Decode signature to binary for some attempts
SIGNATURE_BIN_FILE=$(mktemp /tmp/signature.XXXXXX.bin)
base64 -d "$SIGNATURE_B64_FILE" > "$SIGNATURE_BIN_FILE"

echo "--- Verification attempt 1: base64 statement + base64 signature ---"
cosign verify-blob \
    --key "$CLEAN_KEY_FILE" \
    --signature "$SIGNATURE_B64_FILE" \
    --insecure-ignore-tlog=true \
    "$STATEMENT_B64_FILE" 2>&1
RESULT1=$?

echo ""
echo "--- Verification attempt 2: decoded statement + base64 signature ---"
cosign verify-blob \
    --key "$CLEAN_KEY_FILE" \
    --signature "$SIGNATURE_B64_FILE" \
    --insecure-ignore-tlog=true \
    "$STATEMENT_JSON_FILE" 2>&1
RESULT2=$?

echo ""
echo "--- Verification attempt 3: base64 statement + binary signature ---"
cosign verify-blob \
    --key "$CLEAN_KEY_FILE" \
    --signature "$SIGNATURE_BIN_FILE" \
    --insecure-ignore-tlog=true \
    "$STATEMENT_B64_FILE" 2>&1
RESULT3=$?

echo ""
echo "--- Verification attempt 4: decoded statement + binary signature ---"
cosign verify-blob \
    --key "$CLEAN_KEY_FILE" \
    --signature "$SIGNATURE_BIN_FILE" \
    --insecure-ignore-tlog=true \
    "$STATEMENT_JSON_FILE" 2>&1
RESULT4=$?

set -e

# Summary
echo ""
echo "============================================================"
echo "Verification Results"
echo "============================================================"
echo ""

if [ $RESULT1 -eq 0 ] || [ $RESULT2 -eq 0 ] || [ $RESULT3 -eq 0 ] || [ $RESULT4 -eq 0 ]; then
    echo "✓ SIGNATURE VERIFIED SUCCESSFULLY"
else
    echo "✗ SIGNATURE VERIFICATION FAILED"
    echo ""
    echo "The signature could not be verified with the provided public key."
    echo "This means either:"
    echo "  1. The attestation was signed with a different private key"
    echo "  2. The public key file does not match the signing key"
    echo ""
    echo "Public key used: $PUBLIC_KEY_FILE"
    echo "Key info: $KEY_INFO"
fi

# Cleanup
rm -f "$ATTESTATION_FILE" "$STATEMENT_B64_FILE" "$STATEMENT_JSON_FILE" "$SIGNATURE_B64_FILE" "$SIGNATURE_BIN_FILE" "$CLEAN_KEY_FILE"

echo ""

if [ $RESULT1 -eq 0 ] || [ $RESULT2 -eq 0 ] || [ $RESULT3 -eq 0 ] || [ $RESULT4 -eq 0 ]; then
    exit 0
else
    exit 1
fi
