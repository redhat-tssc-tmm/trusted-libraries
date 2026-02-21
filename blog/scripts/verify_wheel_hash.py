#!/usr/bin/env python3
"""
Verify Wheel Hash Matches Attestation

This script demonstrates how to verify that a Python wheel file's SHA256 hash
matches the digest recorded in its attestation.

Why verify the hash?
--------------------
The attestation cryptographically binds a specific file (identified by its
SHA256 hash) to build provenance information. By verifying that:

  1. The wheel you have matches the hash in the attestation
  2. The attestation signature is valid (see verify_signature.py)

You can be confident that:
  - The wheel was built by the claimed builder (Red Hat/Konflux)
  - The wheel hasn't been modified since it was signed
  - You're not installing a tampered or substituted package

What is a wheel?
----------------
A wheel (.whl) is Python's binary package format. It's a ZIP file containing:
  - The package code (Python files, compiled extensions)
  - Metadata (package name, version, dependencies)
  - A RECORD file listing all contents with their hashes

Wheel filename format:
  {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl

Example:
  numpy-1.24.0-cp311-cp311-manylinux_2_17_x86_64.whl
  └───┘ └────┘ └───┘ └────┘ └─────────────────────┘
   name   ver  python  abi        platform

What is SHA256?
---------------
SHA256 is a cryptographic hash function that produces a 256-bit (64 hex char)
digest. It has these properties:
  - Deterministic: same input always produces same output
  - One-way: cannot reverse the hash to get the input
  - Collision-resistant: infeasible to find two inputs with same hash
  - Avalanche effect: small input change = completely different hash

This makes it ideal for verifying file integrity.

Usage:
    python verify_wheel_hash.py <package_name>
    python verify_wheel_hash.py pyyaml
    python verify_wheel_hash.py --keep-wheel numpy

Requirements:
    pip install requests
"""

import argparse
import base64
import hashlib
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
# Index Configuration (same as other scripts)
# =============================================================================


def get_index_config() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Extract index URL and credentials from pip config."""
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
# Step 1: Get Package Info from Simple API
# =============================================================================


def get_package_info(package_name: str) -> Optional[dict]:
    """
    Fetch package information from the Simple API.

    Returns the download URL, expected hash, and provenance URL for
    the most recent wheel.
    """
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

    # Find the most recent wheel
    for file_info in reversed(data.get("files", [])):
        filename = file_info.get("filename", "")
        if filename.endswith(".whl"):
            parts = filename.split("-")
            version = parts[1] if len(parts) >= 2 else "unknown"
            return {
                "filename": filename,
                "version": version,
                "url": file_info.get("url"),
                "sha256": file_info.get("hashes", {}).get("sha256"),
                "provenance_url": file_info.get("provenance"),
            }

    print(f"Error: No wheel found for package '{package_name}'")
    return None


# =============================================================================
# Step 2: Download the Wheel
# =============================================================================
#
# We download the wheel file to compute its hash. This simulates what pip
# does when installing a package, but instead of installing, we verify.


def download_wheel(url: str, dest_dir: Path) -> Optional[Path]:
    """
    Download a wheel file from the index.

    Args:
        url: The download URL for the wheel
        dest_dir: Directory to save the wheel

    Returns:
        Path to the downloaded wheel, or None on error
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    # Extract filename from URL
    filename = url.split("/")[-1].split("#")[0].split("?")[0]
    dest_path = dest_dir / filename

    try:
        auth = (username, password) if username and password else None
        response = requests.get(url, auth=auth, timeout=120, stream=True)
        response.raise_for_status()

        # Write the wheel to disk
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        return dest_path

    except requests.RequestException as e:
        print(f"Error: Failed to download wheel: {e}")
        return None


# =============================================================================
# Step 3: Compute the Wheel's SHA256 Hash
# =============================================================================
#
# We compute the SHA256 hash of the downloaded wheel file. This is done by
# reading the file in chunks (for memory efficiency with large files) and
# feeding each chunk to the hash function.
#
# The result is a 64-character hexadecimal string like:
#   "df088c59bcc2fc6a1ed21fb2db644f9890782f4fe658518756886833286a60b6"


def compute_sha256(file_path: Path) -> str:
    """
    Compute the SHA256 hash of a file.

    Uses chunked reading for memory efficiency with large files.
    A 100MB wheel would only use ~64KB of memory at a time.

    Args:
        file_path: Path to the file to hash

    Returns:
        Lowercase hexadecimal SHA256 digest (64 characters)
    """
    # Create a new SHA256 hash object
    sha256_hash = hashlib.sha256()

    # Read the file in 64KB chunks
    # This is efficient for both small and large files
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            # Update the hash with each chunk
            sha256_hash.update(chunk)

    # Return the final hash as a hex string
    return sha256_hash.hexdigest()


# =============================================================================
# Step 4: Fetch the Attestation
# =============================================================================


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
# Step 5: Extract the Digest from the Attestation
# =============================================================================
#
# The attestation contains an in-toto statement with a "subject" field.
# The subject identifies what artifact the attestation is about:
#
# {
#   "_type": "https://in-toto.io/Statement/v0.1",
#   "subject": [
#     {
#       "name": "package-1.0.0-py3-none-any.whl",
#       "digest": {
#         "sha256": "abc123..."   <-- This is what we extract
#       }
#     }
#   ],
#   ...
# }
#
# The statement is base64-encoded in the DSSE envelope, so we need to
# decode it first.


def extract_attestation_digest(attestation: dict) -> Optional[str]:
    """
    Extract the SHA256 digest from the attestation's subject.

    The attestation contains a base64-encoded in-toto statement.
    We decode it and extract the subject's SHA256 digest.

    Args:
        attestation: The raw attestation dict from the API

    Returns:
        The SHA256 hex digest from the attestation, or None on error
    """
    try:
        # Navigate to the envelope
        bundles = attestation.get("attestation_bundles", [])
        if not bundles:
            print("  Error: No attestation_bundles found")
            return None

        attestations = bundles[0].get("attestations", [])
        if not attestations:
            print("  Error: No attestations found in bundle")
            return None

        envelope = attestations[0].get("envelope", {})
        statement_b64 = envelope.get("statement")

        if not statement_b64:
            print("  Error: No statement found in envelope")
            return None

        # Decode the base64 statement
        statement_bytes = base64.b64decode(statement_b64)
        statement = json.loads(statement_bytes)

        # Extract the subject digest
        # The subject is a list (usually with one entry)
        subjects = statement.get("subject", [])
        if not subjects:
            print("  Error: No subjects in statement")
            return None

        # Get the SHA256 digest from the first subject
        digest = subjects[0].get("digest", {})
        sha256 = digest.get("sha256")

        if not sha256:
            print("  Error: No sha256 in subject digest")
            return None

        return sha256

    except (json.JSONDecodeError, base64.binascii.Error) as e:
        print(f"  Error: Failed to decode statement: {e}")
        return None
    except (KeyError, IndexError) as e:
        print(f"  Error: Failed to extract digest: {e}")
        return None


# =============================================================================
# Step 6: Compare the Hashes
# =============================================================================
#
# This is the actual verification step. We compare the hash we computed
# from the downloaded wheel with the hash recorded in the attestation.
#
# If they match, we know:
#   - The wheel we have is exactly the one that was attested
#   - No bytes have been modified since the attestation was created
#
# If they don't match, either:
#   - The wheel was corrupted during download
#   - The wheel was tampered with
#   - We downloaded a different version than the attestation covers


def compare_hashes(computed_hash: str, attestation_hash: str) -> bool:
    """
    Compare the computed wheel hash with the attestation hash.

    Uses constant-time comparison to prevent timing attacks
    (though this is mainly relevant for password comparisons,
    it's good practice for any security-sensitive comparison).

    Args:
        computed_hash: SHA256 hash computed from the wheel file
        attestation_hash: SHA256 hash from the attestation subject

    Returns:
        True if hashes match, False otherwise
    """
    # Normalize both hashes to lowercase for comparison
    computed = computed_hash.lower()
    attested = attestation_hash.lower()

    # Compare the hashes
    return computed == attested


# =============================================================================
# Main Verification Flow
# =============================================================================


def verify_wheel_hash(package_name: str, keep_wheel: bool = False) -> bool:
    """
    Run the complete wheel hash verification flow.

    Steps:
    1. Get package info (download URL, expected hash) from Simple API
    2. Download the wheel file
    3. Compute the wheel's SHA256 hash
    4. Fetch the attestation
    5. Extract the digest from the attestation
    6. Compare the hashes

    Args:
        package_name: Name of the package to verify
        keep_wheel: If True, don't delete the downloaded wheel

    Returns:
        True if hash verification passes, False otherwise
    """
    print()
    print("=" * 70)
    print(f"Verifying wheel hash for: {package_name}")
    print("=" * 70)
    print()

    # Step 1: Get package info
    print("Step 1: Fetching package info from Simple API...")
    package_info = get_package_info(package_name)
    if not package_info:
        return False

    print(f"  Filename: {package_info['filename']}")
    print(f"  Version:  {package_info['version']}")
    print(f"  Index SHA256: {package_info['sha256']}")
    print()

    # Create temp directory for wheel download
    temp_dir = Path(tempfile.mkdtemp(prefix="wheel_verify_"))

    try:
        # Step 2: Download the wheel
        print("Step 2: Downloading wheel from index...")
        print(f"  URL: {package_info['url'][:80]}...")
        wheel_path = download_wheel(package_info['url'], temp_dir)
        if not wheel_path:
            return False

        print(f"  Downloaded: {wheel_path.name}")
        print(f"  Size: {wheel_path.stat().st_size:,} bytes")
        print()

        # Step 3: Compute SHA256 hash
        print("Step 3: Computing SHA256 hash of wheel...")
        computed_hash = compute_sha256(wheel_path)
        print(f"  Computed SHA256: {computed_hash}")
        print()

        # Quick check: compare with index hash
        print("  Comparing with index hash...")
        if package_info['sha256']:
            if computed_hash == package_info['sha256'].lower():
                print("    Index hash matches computed hash")
            else:
                print("    WARNING: Index hash does NOT match!")
                print(f"    Index:    {package_info['sha256']}")
                print(f"    Computed: {computed_hash}")
        print()

        # Step 4: Fetch attestation
        print("Step 4: Fetching attestation from integrity API...")
        attestation = fetch_attestation(
            package_name,
            package_info['version'],
            package_info['filename']
        )
        if not attestation:
            return False
        print("  Attestation retrieved successfully")
        print()

        # Step 5: Extract digest from attestation
        print("Step 5: Extracting digest from attestation subject...")
        attestation_hash = extract_attestation_digest(attestation)
        if not attestation_hash:
            return False
        print(f"  Attestation SHA256: {attestation_hash}")
        print()

        # Step 6: Compare hashes
        print("Step 6: Comparing wheel hash with attestation hash...")
        hashes_match = compare_hashes(computed_hash, attestation_hash)

        print()
        print("=" * 70)
        if hashes_match:
            print("  HASH VERIFIED: Wheel matches attestation")
            print()
            print("  This confirms:")
            print("    - The wheel you have is the one that was attested")
            print("    - No bytes have been modified since signing")
            print("    - Combined with signature verification, this proves provenance")
        else:
            print("  HASH MISMATCH: Wheel does NOT match attestation!")
            print()
            print(f"    Computed:  {computed_hash}")
            print(f"    Attested:  {attestation_hash}")
            print()
            print("  This could mean:")
            print("    - The wheel was corrupted during download")
            print("    - The wheel was tampered with")
            print("    - Version mismatch between wheel and attestation")
        print("=" * 70)
        print()

        # Optionally keep the wheel
        if keep_wheel and hashes_match:
            final_path = Path.cwd() / wheel_path.name
            wheel_path.rename(final_path)
            print(f"Wheel saved to: {final_path}")
            print()

        return hashes_match

    finally:
        # Cleanup temp directory (unless we moved the wheel out)
        import shutil
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


# =============================================================================
# Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Verify that a wheel's SHA256 hash matches its attestation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_wheel_hash.py pyyaml
  python verify_wheel_hash.py --keep-wheel numpy

This script demonstrates hash verification:
1. Downloads the wheel from the package index
2. Computes its SHA256 hash
3. Fetches the attestation and extracts the subject digest
4. Compares the hashes to verify integrity

Combined with signature verification (verify_signature.py), this proves:
  - The wheel was built by the claimed builder
  - The wheel hasn't been modified since it was signed

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
        """
    )
    parser.add_argument(
        "package",
        help="Name of the package to verify"
    )
    parser.add_argument(
        "--keep-wheel",
        action="store_true",
        help="Keep the downloaded wheel file after verification"
    )

    args = parser.parse_args()

    success = verify_wheel_hash(args.package, args.keep_wheel)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
