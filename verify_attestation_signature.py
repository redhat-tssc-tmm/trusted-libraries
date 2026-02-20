#!/usr/bin/env python3
"""
Attestation Signature Verification Script

This script fetches an attestation from the Red Hat Trusted Libraries index
and verifies its signature using cosign.

Requirements:
    pip install requests
    cosign CLI tool

Usage:
    python verify_attestation_signature.py <package_name>
    python verify_attestation_signature.py --public-key /path/to/key.pub <package_name>
    python verify_attestation_signature.py amqp
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
# Index Configuration
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


# =============================================================================
# Package Metadata
# =============================================================================

def get_package_metadata(package_name: str) -> Optional[dict]:
    """
    Fetch package metadata from the index using PEP 691 JSON API.

    Args:
        package_name: Name of the package

    Returns:
        Package metadata dict or None if not found
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("Error: Could not get index configuration from pip config")
        return None

    url = f"{base_url}{simple_path}/{package_name}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)

        if resp.status_code == 404:
            print(f"Error: Package '{package_name}' not found in index")
            return None

        resp.raise_for_status()
        return resp.json()

    except requests.RequestException as e:
        print(f"Error: Failed to fetch package metadata: {e}")
        return None


def find_wheel_with_attestation(metadata: dict) -> Optional[dict]:
    """
    Find a wheel file that has an attestation (provenance URL).

    Args:
        metadata: Package metadata from the index

    Returns:
        File info dict with filename, provenance, sha256, or None
    """
    for file_info in metadata.get("files", []):
        filename = file_info.get("filename", "")
        if filename.endswith(".whl") and file_info.get("provenance"):
            return {
                "filename": filename,
                "provenance": file_info.get("provenance"),
                "sha256": file_info.get("hashes", {}).get("sha256"),
                "url": file_info.get("url")
            }

    return None


def extract_version_from_wheel(filename: str) -> str:
    """Extract version from wheel filename."""
    # Format: package-version-...-any.whl
    parts = filename.split("-")
    if len(parts) >= 2:
        return parts[1]
    return "unknown"


# =============================================================================
# Attestation Fetching
# =============================================================================

def fetch_attestation(package_name: str, version: str, filename: str) -> Optional[dict]:
    """
    Fetch attestation from the integrity API.

    Args:
        package_name: Name of the package
        version: Version string
        filename: Wheel filename

    Returns:
        Attestation dict or None
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not repo_name:
        print("Error: Could not get index configuration")
        return None

    attestation_url = f"{base_url}/api/pypi/{repo_name}/main/integrity/{package_name}/{version}/{filename}/provenance/"

    try:
        auth = (username, password) if username and password else None
        resp = requests.get(attestation_url, auth=auth, timeout=30)

        if resp.status_code == 404:
            print(f"Error: No attestation found for {filename}")
            return None

        resp.raise_for_status()
        return resp.json()

    except requests.RequestException as e:
        print(f"Error: Failed to fetch attestation: {e}")
        return None


# =============================================================================
# Attestation Parsing
# =============================================================================

def extract_attestation_envelope(attestation: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Extract base64-encoded statement and signature from attestation.

    Returns:
        Tuple of (statement_b64, signature_b64) or (None, None)
    """
    if "attestation_bundles" not in attestation:
        return None, None

    bundles = attestation["attestation_bundles"]
    if not bundles or len(bundles) == 0:
        return None, None

    bundle = bundles[0]
    if "attestations" not in bundle or len(bundle["attestations"]) == 0:
        return None, None

    att = bundle["attestations"][0]
    if "envelope" not in att:
        return None, None

    envelope = att["envelope"]
    return envelope.get("statement"), envelope.get("signature")


def decode_statement(statement_b64: str) -> Optional[dict]:
    """Decode base64 statement to JSON dict."""
    try:
        return json.loads(base64.b64decode(statement_b64))
    except (json.JSONDecodeError, Exception) as e:
        print(f"Error: Failed to decode statement: {e}")
        return None


def extract_attestation_details(statement: dict) -> dict:
    """Extract key details from the in-toto statement."""
    details = {
        "type": statement.get("_type", "unknown"),
        "predicate_type": statement.get("predicateType", "unknown"),
    }

    # Subject info
    subjects = statement.get("subject", [])
    if subjects:
        details["subject_name"] = subjects[0].get("name", "unknown")
        details["subject_sha256"] = subjects[0].get("digest", {}).get("sha256", "unknown")

    # Predicate info (SLSA provenance)
    predicate = statement.get("predicate", {})
    if "predicate" in predicate:
        # Nested predicate structure
        inner = predicate.get("predicate", {})
        details["builder_id"] = inner.get("builder", {}).get("id", "unknown")
        details["build_finished"] = inner.get("metadata", {}).get("buildFinishedOn", "unknown")
    else:
        details["builder_id"] = predicate.get("builder", {}).get("id", "unknown")
        details["build_finished"] = predicate.get("metadata", {}).get("buildFinishedOn", "unknown")

    return details


# =============================================================================
# DSSE PAE Construction
# =============================================================================

def create_dsse_pae(payload: bytes, payload_type: str = "application/vnd.in-toto+json") -> bytes:
    """
    Create DSSE Pre-Authentication Encoding (PAE).

    Format: DSSEv1 <type_len> <type> <payload_len> <payload>
    """
    type_len = len(payload_type)
    payload_len = len(payload)
    pae_header = f"DSSEv1 {type_len} {payload_type} {payload_len} ".encode("utf-8")
    return pae_header + payload


# =============================================================================
# Signature Verification
# =============================================================================

def check_cosign_available() -> bool:
    """Check if cosign CLI is available."""
    try:
        result = subprocess.run(
            ["cosign", "version"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def verify_signature(
    statement_b64: str,
    signature_b64: str,
    public_key_path: Path
) -> tuple[bool, str]:
    """
    Verify the attestation signature using cosign.

    Args:
        statement_b64: Base64-encoded statement
        signature_b64: Base64-encoded signature
        public_key_path: Path to public key file

    Returns:
        Tuple of (success, message)
    """
    if not public_key_path.exists():
        return False, f"Public key not found: {public_key_path}"

    # Decode statement and signature
    try:
        statement_bytes = base64.b64decode(statement_b64)
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        return False, f"Failed to decode base64: {e}"

    # Create DSSE PAE
    pae_bytes = create_dsse_pae(statement_bytes)

    # Write temporary files
    with tempfile.TemporaryDirectory(prefix="cosign_verify_") as temp_dir:
        temp_path = Path(temp_dir)

        pae_file = temp_path / "pae.bin"
        pae_file.write_bytes(pae_bytes)

        sig_file = temp_path / "signature.bin"
        sig_file.write_bytes(signature_bytes)

        # Clean the public key (extract PEM portion)
        clean_key_file = temp_path / "clean_key.pub"
        key_content = public_key_path.read_text()
        pem_match = re.search(
            r"(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
            key_content,
            re.DOTALL
        )
        if pem_match:
            clean_key_file.write_text(pem_match.group(1))
        else:
            clean_key_file.write_text(key_content)

        # Run cosign verify-blob
        result = subprocess.run(
            [
                "cosign", "verify-blob",
                "--key", str(clean_key_file),
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
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return False, f"Verification failed: {error_msg}"


# =============================================================================
# Main
# =============================================================================

def get_default_public_key_path() -> Path:
    """Get default public key path (redhat-release3.pub in script directory)."""
    return Path(__file__).parent.resolve() / "redhat-release3.pub"


def verify_attestation(package_name: str, public_key_path: Path, show_full: bool = False) -> bool:
    """
    Verify attestation signature for a package.

    Args:
        package_name: Name of the package
        public_key_path: Path to the public key
        show_full: If True, show full attestation JSON

    Returns:
        True if verification passed, False otherwise
    """
    print("=" * 60)
    print("Attestation Signature Verification")
    print("=" * 60)
    print()
    print(f"Package:    {package_name}")
    print(f"Public Key: {public_key_path}")
    print()

    # Step 1: Check cosign
    print("[1/8] Checking cosign availability...")
    if not check_cosign_available():
        print("       Error: cosign is not installed or not available")
        return False
    print("       cosign: OK")

    # Step 2: Get package metadata
    print()
    print("[2/8] Querying package metadata...")
    metadata = get_package_metadata(package_name)
    if not metadata:
        return False
    print("       Package found: OK")

    # Step 3: Find wheel with attestation
    print()
    print("[3/8] Finding wheel with attestation...")
    wheel_info = find_wheel_with_attestation(metadata)
    if not wheel_info:
        # Check if any wheels exist
        wheels = [f for f in metadata.get("files", []) if f.get("filename", "").endswith(".whl")]
        if not wheels:
            print("       Error: No wheels available for this package")
        else:
            print("       Error: No wheels with attestations found")
            print("       Available wheels (without attestations):")
            for w in wheels[:5]:
                print(f"         - {w.get('filename')}")
        return False

    filename = wheel_info["filename"]
    version = extract_version_from_wheel(filename)

    print(f"       Wheel: {filename}")
    print(f"       Version: {version}")
    print("       Attestation available: Yes")

    # Step 4: Fetch attestation
    print()
    print("[4/8] Fetching attestation from integrity API...")
    attestation = fetch_attestation(package_name, version, filename)
    if not attestation:
        return False
    print("       Attestation fetched: OK")

    # Step 5: Extract statement and signature
    print()
    print("[5/8] Extracting statement and signature...")
    statement_b64, signature_b64 = extract_attestation_envelope(attestation)
    if not statement_b64 or not signature_b64:
        print("       Error: Could not extract statement/signature from attestation")
        return False
    print("       Statement extracted: OK")
    print("       Signature extracted: OK")

    # Step 6: Display attestation details
    print()
    print("[6/8] Attestation details:")
    statement = decode_statement(statement_b64)
    if statement:
        details = extract_attestation_details(statement)
        print()
        print(f"       Subject: {details.get('subject_name', 'unknown')}")
        print(f"       SHA256:  {details.get('subject_sha256', 'unknown')}")
        print(f"       Builder: {details.get('builder_id', 'unknown')}")
        print(f"       Built:   {details.get('build_finished', 'unknown')}")
        print()

        # Signature info
        sig_decoded = base64.b64decode(signature_b64)
        sig_preview = signature_b64[:60]
        print(f"       Signature (base64, first 60 chars): {sig_preview}...")
        print(f"       Signature decoded length: {len(sig_decoded)} bytes")

    if show_full:
        print()
        print("--- Full Attestation (raw from API) ---")
        print(json.dumps(attestation, indent=2))
        print()
        print("--- Decoded Statement ---")
        if statement:
            print(json.dumps(statement, indent=2))

    # Step 7: Prepare public key
    print()
    print("[7/8] Preparing public key...")
    if not public_key_path.exists():
        print(f"       Error: Public key not found: {public_key_path}")
        return False

    # Get key info
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(public_key_path), "-text", "-noout"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            key_type = result.stdout.split('\n')[0] if result.stdout else "Unknown"
            print(f"       Key type: {key_type}")
    except FileNotFoundError:
        print("       Key type: (openssl not available to detect)")

    # Step 8: Verify signature
    print()
    print("[8/8] Verifying signature with cosign...")
    print()
    print("       Verifying DSSE signature against PAE...")

    # Show PAE info
    statement_bytes = base64.b64decode(statement_b64)
    pae_bytes = create_dsse_pae(statement_bytes)
    print(f"       PAE size: {len(pae_bytes)} bytes")
    print(f"       PAE format: DSSEv1 <type_len> <type> <payload_len> <payload>")
    print(f"       Payload type: application/vnd.in-toto+json (27 bytes)")
    print(f"       Payload length: {len(statement_bytes)} bytes")
    print()

    success, message = verify_signature(statement_b64, signature_b64, public_key_path)

    # Summary
    print()
    print("=" * 60)
    print("Verification Results")
    print("=" * 60)
    print()

    if success:
        print("SIGNATURE VERIFIED SUCCESSFULLY")
        print()
        print("The attestation signature is valid and was created with the")
        print(f"private key corresponding to: {public_key_path}")
        print()
        print("This confirms the attestation was signed by the expected authority.")
    else:
        print("SIGNATURE VERIFICATION FAILED")
        print()
        print(f"Error: {message}")
        print()
        print("This means either:")
        print("  1. The attestation was signed with a different private key")
        print("  2. The public key file does not match the signing key")
        print("  3. The attestation data has been tampered with")

    print()
    return success


def main():
    parser = argparse.ArgumentParser(
        description="Verify attestation signatures for packages from Red Hat Trusted Libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s amqp                                    # Verify with default key
  %(prog)s --public-key ../redhat-release3.pub amqp  # Use custom key
  %(prog)s --full amqp                             # Show full attestation JSON

This script:
  1. Queries the package index for available wheels with attestations
  2. Fetches the attestation from the integrity API
  3. Extracts the in-toto statement and signature
  4. Constructs the DSSE PAE (Pre-Authentication Encoding)
  5. Verifies the signature using cosign

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
      Requires cosign CLI to be installed.
        """
    )
    parser.add_argument(
        "package",
        help="Package name to verify"
    )
    parser.add_argument(
        "--public-key", "-k",
        type=Path,
        default=None,
        help="Path to public key (default: redhat-release3.pub in script directory)"
    )
    parser.add_argument(
        "--full", "-f",
        action="store_true",
        help="Show full attestation and statement JSON"
    )

    args = parser.parse_args()

    # Determine public key path
    if args.public_key:
        public_key_path = args.public_key.resolve()
    else:
        default_key = get_default_public_key_path()
        if default_key.exists():
            public_key_path = default_key
        else:
            print(f"Error: Default public key not found at {default_key}")
            print("       Use --public-key to specify a key path.")
            sys.exit(1)

    success = verify_attestation(args.package, public_key_path, show_full=args.full)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
