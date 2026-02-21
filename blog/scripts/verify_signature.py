#!/usr/bin/env python3
"""
Verify Attestation Signature with Cosign

This script demonstrates how to verify the cryptographic signature on a
package attestation using the cosign CLI tool.

What is signature verification?
-------------------------------
Attestations are cryptographically signed to prove they haven't been tampered
with and come from a trusted source (in this case, Red Hat). The signature
is created using a private key held by the signer, and can be verified using
the corresponding public key.

What is DSSE?
-------------
DSSE (Dead Simple Signing Envelope) is a standard format for signing arbitrary
data. It wraps the payload (the in-toto statement) with:
  - A payload type identifier
  - The base64-encoded payload
  - One or more signatures

What is PAE?
------------
PAE (Pre-Authentication Encoding) is how the data is prepared before signing.
Instead of signing the raw payload, DSSE signs a structured message that
includes the payload type and length. This prevents several attacks:

  1. Type confusion attacks: By binding the payload type to the signature,
     an attacker cannot take a valid signature from one context (e.g., a
     config file) and apply it to another (e.g., an attestation).

  2. Length extension attacks: By including explicit lengths, attackers
     cannot append malicious data to a signed message.

  3. Ambiguity attacks: The structured format ensures there's exactly one
     way to interpret the signed data.

See the DSSE specification for details:
  https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

PAE format: "DSSEv1 <type_len> <type> <payload_len> <payload>"

Example: "DSSEv1 28 application/vnd.in-toto+json 1234 {\"_type\":...}"

Usage:
    python verify_signature.py <package_name>
    python verify_signature.py pyyaml
    python verify_signature.py --public-key /path/to/key.pub numpy

Requirements:
    pip install requests
    cosign CLI tool (https://docs.sigstore.dev/cosign/installation/)
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


# =============================================================================
# Index Configuration (same as fetch_attestation.py)
# =============================================================================


def get_index_config() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract index URL and credentials from pip config.

    Returns:
        Tuple of (base_url, simple_path, repo_name, username, password)
    """
    result = subprocess.run(
        ["pip", "config", "list"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None, None, None, None, None

    match = re.search(r"global\.index-url='([^']+)'", result.stdout)
    if not match:
        return None, None, None, None, None

    full_url = match.group(1)
    parsed = urlparse(full_url)

    if parsed.username and parsed.password:
        base_url = f"{parsed.scheme}://{parsed.hostname}"
        simple_path = parsed.path.rstrip("/")
        path_parts = [p for p in parsed.path.split("/") if p]
        repo_name = path_parts[0] if path_parts else None
        return base_url, simple_path, repo_name, unquote(parsed.username), unquote(parsed.password)

    return full_url, None, None, None, None


def normalize_package_name(name: str) -> str:
    """Normalize a package name according to PEP 503."""
    return re.sub(r'[-_.]+', '-', name).lower()


# =============================================================================
# Fetch Package Info and Attestation
# =============================================================================


def get_package_info(package_name: str) -> Optional[dict]:
    """Fetch package information from the Simple API."""
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("Error: Could not get index configuration from pip config")
        return None

    normalized_name = normalize_package_name(package_name)
    url = f"{base_url}{simple_path}/{normalized_name}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        response = requests.get(url, auth=auth, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"Error: Failed to fetch package info: {e}")
        return None

    for file_info in reversed(data.get("files", [])):
        filename = file_info.get("filename", "")
        if filename.endswith(".whl"):
            parts = filename.split("-")
            version = parts[1] if len(parts) >= 2 else "unknown"
            return {
                "filename": filename,
                "version": version,
                "sha256": file_info.get("hashes", {}).get("sha256"),
                "provenance_url": file_info.get("provenance"),
            }

    print(f"Error: No wheel found for package '{package_name}'")
    return None


def fetch_attestation(package_name: str, version: str, filename: str) -> Optional[dict]:
    """Fetch the attestation for a specific package file."""
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not repo_name:
        print("Error: Could not get index configuration")
        return None

    normalized_name = normalize_package_name(package_name)
    attestation_url = (
        f"{base_url}/api/pypi/{repo_name}/main/integrity/"
        f"{normalized_name}/{version}/{filename}/provenance/"
    )

    try:
        auth = (username, password) if username and password else None
        response = requests.get(attestation_url, auth=auth, timeout=30)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"No attestation found for this package")
            return None
        else:
            print(f"Error: Attestation request returned {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error: Failed to fetch attestation: {e}")
        return None


# =============================================================================
# Step 1: Extract the DSSE Envelope Components
# =============================================================================
#
# The attestation contains a DSSE (Dead Simple Signing Envelope) with:
#   - statement: base64-encoded in-toto statement (the payload)
#   - signature: base64-encoded cryptographic signature
#
# We need to extract both to verify the signature.


def extract_envelope_components(attestation: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Extract the statement and signature from the attestation envelope.

    The attestation structure is:
    {
        "attestation_bundles": [
            {
                "attestations": [
                    {
                        "envelope": {
                            "statement": "<base64-encoded in-toto statement>",
                            "signature": "<base64-encoded signature>"
                        }
                    }
                ]
            }
        ]
    }

    Args:
        attestation: The raw attestation dict from the API

    Returns:
        Tuple of (statement_base64, signature_base64) or (None, None)
    """
    try:
        bundles = attestation.get("attestation_bundles", [])
        if not bundles:
            print("  Error: No attestation_bundles found")
            return None, None

        attestations = bundles[0].get("attestations", [])
        if not attestations:
            print("  Error: No attestations found in bundle")
            return None, None

        envelope = attestations[0].get("envelope", {})
        statement_b64 = envelope.get("statement")
        signature_b64 = envelope.get("signature")

        if not statement_b64:
            print("  Error: No statement found in envelope")
            return None, None

        if not signature_b64:
            print("  Error: No signature found in envelope")
            return None, None

        return statement_b64, signature_b64

    except (KeyError, IndexError) as e:
        print(f"  Error: Failed to extract envelope components: {e}")
        return None, None


# =============================================================================
# Step 2: Decode Base64 Components
# =============================================================================
#
# Both the statement and signature are base64-encoded. We need to decode
# them to their raw binary form for signature verification.


def decode_base64_components(
    statement_b64: str, signature_b64: str
) -> tuple[Optional[bytes], Optional[bytes]]:
    """
    Decode the base64-encoded statement and signature.

    Args:
        statement_b64: Base64-encoded in-toto statement
        signature_b64: Base64-encoded signature

    Returns:
        Tuple of (statement_bytes, signature_bytes) or (None, None)
    """
    try:
        statement_bytes = base64.b64decode(statement_b64)
        signature_bytes = base64.b64decode(signature_b64)
        return statement_bytes, signature_bytes
    except Exception as e:
        print(f"  Error: Failed to decode base64: {e}")
        return None, None


# =============================================================================
# Step 3: Create the DSSE PAE (Pre-Authentication Encoding)
# =============================================================================
#
# This is the critical step! The signature is NOT over the raw statement.
# Instead, it's over a PAE (Pre-Authentication Encoding) that includes
# metadata about the payload type and length.
#
# PAE Format:
#   "DSSEv1 {type_length} {type} {payload_length} {payload}"
#
# Where:
#   - "DSSEv1" is a literal string identifying the format version
#   - {type_length} is the decimal length of the type string
#   - {type} is "application/vnd.in-toto+json" for in-toto statements
#   - {payload_length} is the decimal length of the payload in bytes
#   - {payload} is the raw payload bytes (the decoded statement)
#
# Example for a 1234-byte statement:
#   "DSSEv1 28 application/vnd.in-toto+json 1234 <statement_bytes>"
#
# The spaces are literal ASCII space characters (0x20).


def create_dsse_pae(payload: bytes, payload_type: str = "application/vnd.in-toto+json") -> bytes:
    """
    Create the DSSE Pre-Authentication Encoding (PAE) for signature verification.

    This constructs the exact bytes that were signed. The signature is over
    this PAE, not the raw payload, which provides additional security by
    binding the payload type to the signature.

    Args:
        payload: The raw payload bytes (decoded in-toto statement)
        payload_type: The MIME type of the payload

    Returns:
        The PAE bytes ready for signature verification
    """
    # Get the lengths as decimal strings
    type_len = len(payload_type)
    payload_len = len(payload)

    # Construct the PAE header
    # Format: "DSSEv1 {type_len} {type} {payload_len} "
    # Note the trailing space before the payload
    pae_header = f"DSSEv1 {type_len} {payload_type} {payload_len} ".encode("utf-8")

    # Concatenate header and payload
    pae = pae_header + payload

    return pae


# =============================================================================
# Step 4: Prepare the Public Key
# =============================================================================
#
# The public key is used to verify signatures created with the corresponding
# private key. Red Hat provides their public key in PEM format.
#
# PEM format looks like:
#   -----BEGIN PUBLIC KEY-----
#   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
#   -----END PUBLIC KEY-----
#
# Some key files may contain additional text (comments, metadata).
# We extract just the PEM block for cosign.


def prepare_public_key(key_path: Path, temp_dir: Path) -> Optional[Path]:
    """
    Prepare the public key for cosign verification.

    Extracts the PEM block from the key file, handling any extra content
    that might be present (comments, metadata, etc.).

    Args:
        key_path: Path to the public key file
        temp_dir: Temporary directory to write cleaned key

    Returns:
        Path to the cleaned key file, or None on error
    """
    if not key_path.exists():
        print(f"  Error: Public key not found: {key_path}")
        return None

    key_content = key_path.read_text()

    # Extract the PEM block using regex
    # This handles keys with extra comments or metadata
    pem_match = re.search(
        r"(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
        key_content,
        re.DOTALL  # Allow . to match newlines
    )

    clean_key_path = temp_dir / "clean_key.pub"

    if pem_match:
        # Write just the PEM block
        clean_key_path.write_text(pem_match.group(1))
    else:
        # No PEM markers found, try using the key as-is
        print("  Warning: No PEM markers found in key file, using as-is")
        clean_key_path.write_text(key_content)

    return clean_key_path


# =============================================================================
# Step 5: Verify with Cosign
# =============================================================================
#
# Cosign is a tool from the Sigstore project for signing and verifying
# software artifacts. We use its "verify-blob" command to verify that
# the signature over our PAE is valid.
#
# Command:
#   cosign verify-blob --key <public_key> --signature <sig_file> <pae_file>
#
# Options:
#   --key: Path to the public key file (PEM format)
#   --signature: Path to the binary signature file
#   --insecure-ignore-tlog: Skip transparency log verification
#                           (needed for signatures not in Rekor)
#
# Exit code 0 means the signature is valid.


def verify_with_cosign(
    pae_bytes: bytes,
    signature_bytes: bytes,
    public_key_path: Path
) -> tuple[bool, str]:
    """
    Verify the signature using cosign.

    This writes the PAE and signature to temporary files, then runs
    cosign verify-blob to check if the signature is valid.

    Args:
        pae_bytes: The DSSE PAE (what was signed)
        signature_bytes: The raw signature bytes
        public_key_path: Path to the public key file

    Returns:
        Tuple of (success, message)
    """
    # First, check if cosign is installed
    try:
        result = subprocess.run(
            ["cosign", "version"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False, "cosign not available (version check failed)"
    except FileNotFoundError:
        return False, "cosign not installed (command not found)"

    # Create temporary directory for files
    with tempfile.TemporaryDirectory(prefix="cosign_verify_") as temp_dir:
        temp_path = Path(temp_dir)

        # Write the PAE to a file
        pae_file = temp_path / "pae.bin"
        pae_file.write_bytes(pae_bytes)

        # Write the signature to a file
        sig_file = temp_path / "signature.bin"
        sig_file.write_bytes(signature_bytes)

        # Prepare the public key
        clean_key = prepare_public_key(public_key_path, temp_path)
        if not clean_key:
            return False, "Failed to prepare public key"

        # Run cosign verify-blob
        # --insecure-ignore-tlog: Skip Rekor transparency log check
        #   (Red Hat's signatures aren't in Rekor)
        result = subprocess.run(
            [
                "cosign", "verify-blob",
                "--key", str(clean_key),
                "--signature", str(sig_file),
                "--insecure-ignore-tlog=true",
                str(pae_file)
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return True, "Signature verified successfully"
        else:
            # Extract error message from stderr
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return False, f"Signature verification failed: {error_msg}"


# =============================================================================
# Main Verification Flow
# =============================================================================


def verify_attestation_signature(package_name: str, public_key_path: Path) -> bool:
    """
    Run the complete signature verification flow.

    Steps:
    1. Fetch package info from the Simple API
    2. Fetch the attestation from the integrity API
    3. Extract statement and signature from the DSSE envelope
    4. Decode the base64-encoded components
    5. Create the DSSE PAE (Pre-Authentication Encoding)
    6. Verify the signature using cosign

    Args:
        package_name: Name of the package to verify
        public_key_path: Path to the public key file

    Returns:
        True if signature verification passes, False otherwise
    """
    print()
    print("=" * 70)
    print(f"Verifying attestation signature for: {package_name}")
    print("=" * 70)
    print()

    # Step 1: Get package info
    print("Step 1: Fetching package info from Simple API...")
    package_info = get_package_info(package_name)
    if not package_info:
        return False

    print(f"  Package: {package_info['filename']}")
    print(f"  Version: {package_info['version']}")
    print()

    # Step 2: Fetch attestation
    print("Step 2: Fetching attestation from integrity API...")
    attestation = fetch_attestation(
        package_name,
        package_info['version'],
        package_info['filename']
    )
    if not attestation:
        return False
    print("  Attestation retrieved successfully")
    print()

    # Step 3: Extract envelope components
    print("Step 3: Extracting DSSE envelope components...")
    statement_b64, signature_b64 = extract_envelope_components(attestation)
    if not statement_b64 or not signature_b64:
        return False

    print(f"  Statement (base64): {statement_b64[:50]}...")
    print(f"  Signature (base64): {signature_b64[:50]}...")
    print()

    # Step 4: Decode base64
    print("Step 4: Decoding base64 components...")
    statement_bytes, signature_bytes = decode_base64_components(statement_b64, signature_b64)
    if not statement_bytes or not signature_bytes:
        return False

    print(f"  Statement size: {len(statement_bytes)} bytes")
    print(f"  Signature size: {len(signature_bytes)} bytes")
    print()

    # Show the decoded statement for reference
    try:
        statement_json = json.loads(statement_bytes)
        print("  Decoded statement preview:")
        subjects = statement_json.get("subject", [])
        if subjects:
            print(f"    Subject: {subjects[0].get('name', 'N/A')}")
            print(f"    SHA256:  {subjects[0].get('digest', {}).get('sha256', 'N/A')}")
    except json.JSONDecodeError:
        print("  Warning: Could not parse statement as JSON")
    print()

    # Step 5: Create DSSE PAE
    print("Step 5: Creating DSSE PAE (Pre-Authentication Encoding)...")
    pae_bytes = create_dsse_pae(statement_bytes)

    # Show the PAE header for educational purposes
    pae_header = pae_bytes[:100].decode("utf-8", errors="replace")
    print(f"  PAE header: {pae_header}...")
    print(f"  PAE total size: {len(pae_bytes)} bytes")
    print()

    # Step 6: Verify with cosign
    print("Step 6: Verifying signature with cosign...")
    print(f"  Public key: {public_key_path}")

    success, message = verify_with_cosign(pae_bytes, signature_bytes, public_key_path)

    print()
    print("=" * 70)
    if success:
        print(f"  SIGNATURE VALID: {message}")
    else:
        print(f"  SIGNATURE INVALID: {message}")
    print("=" * 70)
    print()

    return success


# =============================================================================
# Main
# =============================================================================


def get_default_public_key_path() -> Path:
    """Get the default public key path (redhat-release3.pub in parent's parent directory)."""
    script_dir = Path(__file__).parent.resolve()
    # Go up two levels: blog/scripts -> blog -> pulp-index
    return script_dir.parent.parent / "redhat-release3.pub"


def main():
    parser = argparse.ArgumentParser(
        description="Verify attestation signature using cosign",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_signature.py pyyaml
  python verify_signature.py --public-key /path/to/key.pub numpy

This script demonstrates DSSE signature verification:
1. Fetches the attestation containing the signed statement
2. Extracts the base64-encoded statement and signature
3. Creates the DSSE PAE (Pre-Authentication Encoding)
4. Uses cosign to verify the RSA signature

Requirements:
  - pip configured with Red Hat Trusted Libraries index URL
  - cosign CLI tool installed (https://docs.sigstore.dev/cosign/installation/)
  - Public key file (default: ../../redhat-release3.pub)
        """
    )
    parser.add_argument(
        "package",
        help="Name of the package to verify"
    )
    parser.add_argument(
        "--public-key", "-k",
        type=Path,
        default=None,
        help="Path to public key file (default: ../../redhat-release3.pub)"
    )

    args = parser.parse_args()

    # Determine public key path
    if args.public_key:
        public_key_path = args.public_key.resolve()
    else:
        public_key_path = get_default_public_key_path()

    if not public_key_path.exists():
        print(f"Error: Public key not found: {public_key_path}")
        print("Use --public-key to specify the path to the Red Hat public key.")
        sys.exit(1)

    success = verify_attestation_signature(args.package, public_key_path)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
