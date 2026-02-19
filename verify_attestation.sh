#!/bin/bash
#
# Attestation Signature Verification Script
#
# This script fetches an attestation from the Red Hat Trusted Libraries index
# and attempts to verify its signature using cosign.
#
# Usage:
#   ./verify_attestation.sh <package_name> <public_key_file>
#
# Example:
#   ./verify_attestation.sh typer ../redhat-release3.pub
#   ./verify_attestation.sh amqp ../redhat-release3.pub
#

set -e

# Check arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <package_name> <public_key_file>"
    echo ""
    echo "Example: $0 typer ../redhat-release3.pub"
    echo "         $0 amqp ../redhat-release3.pub"
    exit 1
fi

PACKAGE="$1"
PUBLIC_KEY_FILE="$2"

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
echo "Public Key: ${PUBLIC_KEY_FILE}"
echo ""

# Step 1: Get index URL from pip config
echo "[1/8] Getting index URL from pip config..."
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

# Step 2: Query package metadata to find available wheels
echo ""
echo "[2/8] Querying package metadata..."

PACKAGE_META_FILE=$(mktemp /tmp/package-meta.XXXXXX.json)
PACKAGE_URL="${INDEX_URL}${PACKAGE}/"

HTTP_CODE=$(curl -s -w "%{http_code}" -o "$PACKAGE_META_FILE" -H "Accept: application/vnd.pypi.simple.v1+json" "$PACKAGE_URL")

if [ "$HTTP_CODE" != "200" ]; then
    echo "       Error: Package '${PACKAGE}' not found in index (HTTP $HTTP_CODE)"
    rm -f "$PACKAGE_META_FILE"
    exit 1
fi

# Find a wheel with attestation (provenance URL)
WHEEL_INFO=$(jq -r '.files[] | select(.filename | endswith(".whl")) | select(.provenance != null) | "\(.filename)|\(.provenance)"' "$PACKAGE_META_FILE" | head -1)

if [ -z "$WHEEL_INFO" ]; then
    # No wheel with attestation, check if any wheels exist
    WHEEL_COUNT=$(jq -r '[.files[] | select(.filename | endswith(".whl"))] | length' "$PACKAGE_META_FILE")

    if [ "$WHEEL_COUNT" -eq 0 ]; then
        echo "       Error: No wheels available for package '${PACKAGE}'"
        echo ""
        echo "       Available files:"
        jq -r '.files[].filename' "$PACKAGE_META_FILE" | head -10
    else
        echo "       Error: No wheels with attestations found for package '${PACKAGE}'"
        echo ""
        echo "       Available wheels (without attestations):"
        jq -r '.files[] | select(.filename | endswith(".whl")) | .filename' "$PACKAGE_META_FILE" | head -10
    fi
    rm -f "$PACKAGE_META_FILE"
    exit 1
fi

# Parse the wheel info
FILENAME=$(echo "$WHEEL_INFO" | cut -d'|' -f1)
PROVENANCE_URL=$(echo "$WHEEL_INFO" | cut -d'|' -f2)

# Extract version from filename (format: package-version-...-any.whl)
VERSION=$(echo "$FILENAME" | sed -E 's/^[^-]+-([^-]+)-.*/\1/')

echo "       Package found: OK"
echo "       Wheel: ${FILENAME}"
echo "       Version: ${VERSION}"
echo "       Attestation available: Yes"

rm -f "$PACKAGE_META_FILE"

# Update display
echo ""
echo "Selected wheel: ${FILENAME}"
echo ""

# Step 3: Fetch the attestation
echo ""
echo "[3/8] Fetching attestation from integrity API..."
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

# Step 4: Extract statement and signature
echo ""
echo "[4/8] Extracting statement and signature..."

STATEMENT_B64_FILE=$(mktemp /tmp/statement.XXXXXX.b64)
STATEMENT_JSON_FILE=$(mktemp /tmp/statement.XXXXXX.json)
SIGNATURE_B64_FILE=$(mktemp /tmp/signature.XXXXXX.b64)

jq -r '.attestation_bundles[0].attestations[0].envelope.statement' "$ATTESTATION_FILE" > "$STATEMENT_B64_FILE"
jq -r '.attestation_bundles[0].attestations[0].envelope.signature' "$ATTESTATION_FILE" > "$SIGNATURE_B64_FILE"

# Decode statement for display
base64 -d "$STATEMENT_B64_FILE" > "$STATEMENT_JSON_FILE"

echo "       Statement extracted: OK"
echo "       Signature extracted: OK"

# Step 5: Display attestation details
echo ""
echo "[5/8] Attestation details:"
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

# Step 6: Clean the public key (remove any extra lines before PEM header)
echo ""
echo "[6/8] Preparing public key..."

CLEAN_KEY_FILE=$(mktemp /tmp/clean-key.XXXXXX.pub)
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$PUBLIC_KEY_FILE" > "$CLEAN_KEY_FILE"

if [ ! -s "$CLEAN_KEY_FILE" ]; then
    echo "       Error: Could not extract PEM public key from $PUBLIC_KEY_FILE"
    exit 1
fi

# Detect key type
KEY_INFO=$(openssl pkey -pubin -in "$CLEAN_KEY_FILE" -text -noout 2>/dev/null | head -1)
echo "       Key type: $KEY_INFO"

# Step 7: Create DSSE PAE (Pre-Authentication Encoding)
echo ""
echo "[7/8] Creating DSSE Pre-Authentication Encoding (PAE)..."
echo ""
echo "       The attestation uses DSSE (Dead Simple Signing Envelope) format."
echo "       The signature is computed over the PAE, not the raw statement."
echo ""

# Decode the base64 statement to get the raw payload
PAYLOAD_FILE=$(mktemp /tmp/payload.XXXXXX.bin)
base64 -d "$STATEMENT_B64_FILE" > "$PAYLOAD_FILE"

# Get payload length in bytes
PAYLOAD_LEN=$(wc -c < "$PAYLOAD_FILE")

# DSSE payload type for in-toto statements
PAYLOAD_TYPE="application/vnd.in-toto+json"
PAYLOAD_TYPE_LEN=${#PAYLOAD_TYPE}

# Construct PAE: "DSSEv1" + SP + len(type) + SP + type + SP + len(payload) + SP + payload
PAE_FILE=$(mktemp /tmp/pae.XXXXXX.bin)
{
    printf "DSSEv1 %d %s %d " "$PAYLOAD_TYPE_LEN" "$PAYLOAD_TYPE" "$PAYLOAD_LEN"
    cat "$PAYLOAD_FILE"
} > "$PAE_FILE"

PAE_SIZE=$(wc -c < "$PAE_FILE")
echo "       PAE size: ${PAE_SIZE} bytes"
echo "       PAE format: DSSEv1 <type_len> <type> <payload_len> <payload>"
echo "       Payload type: ${PAYLOAD_TYPE} (${PAYLOAD_TYPE_LEN} bytes)"
echo "       Payload length: ${PAYLOAD_LEN} bytes"

# Step 8: Verify signature with cosign
echo ""
echo "[8/8] Verifying signature with cosign..."
echo ""
echo "       Verifying DSSE signature against PAE..."
echo "       Command: cosign verify-blob --key $PUBLIC_KEY_FILE --signature <sig.bin> --insecure-ignore-tlog=true <pae.bin>"
echo ""

# Try verification
set +e  # Don't exit on error for this section

# Decode signature to binary
SIGNATURE_BIN_FILE=$(mktemp /tmp/signature.XXXXXX.bin)
base64 -d "$SIGNATURE_B64_FILE" > "$SIGNATURE_BIN_FILE"

cosign verify-blob \
    --key "$CLEAN_KEY_FILE" \
    --signature "$SIGNATURE_BIN_FILE" \
    --insecure-ignore-tlog=true \
    "$PAE_FILE" 2>&1
RESULT=$?

set -e

# Summary
echo ""
echo "============================================================"
echo "Verification Results"
echo "============================================================"
echo ""

if [ $RESULT -eq 0 ]; then
    echo "✓ SIGNATURE VERIFIED SUCCESSFULLY"
    echo ""
    echo "The attestation signature is valid and was created with the"
    echo "private key corresponding to: $PUBLIC_KEY_FILE"
    echo ""
    echo "This confirms the attestation was signed by the expected authority."
else
    echo "✗ SIGNATURE VERIFICATION FAILED"
    echo ""
    echo "The signature could not be verified with the provided public key."
    echo "This means either:"
    echo "  1. The attestation was signed with a different private key"
    echo "  2. The public key file does not match the signing key"
    echo "  3. The attestation data has been tampered with"
    echo ""
    echo "Public key used: $PUBLIC_KEY_FILE"
    echo "Key info: $KEY_INFO"
fi

# Cleanup
rm -f "$ATTESTATION_FILE" "$STATEMENT_B64_FILE" "$STATEMENT_JSON_FILE" "$SIGNATURE_B64_FILE" "$SIGNATURE_BIN_FILE" "$CLEAN_KEY_FILE" "$PAE_FILE" "$PAYLOAD_FILE"

echo ""

if [ $RESULT -eq 0 ]; then
    exit 0
else
    exit 1
fi
