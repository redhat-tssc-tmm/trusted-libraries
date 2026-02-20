#!/usr/bin/env python3
"""
Package Provenance Verification Tool

This script verifies that an installed Python package matches its published
attestation by:
1. Finding/downloading the original wheel file
2. Computing its SHA256 hash
3. Fetching the attestation from Red Hat Trusted Libraries (Pulp)
4. Comparing the attestation's subject digest to the wheel's hash
5. Verifying the attestation signature using cosign (DSSE PAE format)
6. Verifying installed files match the wheel's RECORD

Requirements:
    pip install requests
    cosign CLI tool (for signature verification)

Usage:
    python verify_package_provenance.py <package_name>
    python verify_package_provenance.py requests
    python verify_package_provenance.py --public-key /path/to/key.pub requests
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

# importlib.metadata is in stdlib since Python 3.8
from importlib.metadata import distribution, PackageNotFoundError

from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


# =============================================================================
# Red Hat Trusted Libraries Index Configuration
# =============================================================================

def get_index_config() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract index URL and credentials from pip config.

    Returns:
        Tuple of (base_url, simple_path, repo_name, username, password)
        - base_url: scheme://hostname (e.g., https://packages.redhat.com)
        - simple_path: full path for simple API (e.g., /trusted-libraries/python)
        - repo_name: repository name for integrity API (e.g., trusted-libraries)
        - username: authentication username
        - password: authentication password
    """
    result = subprocess.run(
        ["pip", "config", "list"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None, None, None, None, None

    # Parse the index-url from pip config output
    match = re.search(r"global\.index-url='([^']+)'", result.stdout)
    if not match:
        return None, None, None, None, None

    full_url = match.group(1)

    # Parse URL with embedded credentials: https://user:pass@host/path/
    parsed = urlparse(full_url)

    if parsed.username and parsed.password:
        base_url = f"{parsed.scheme}://{parsed.hostname}"
        # Full path for simple API (e.g., /trusted-libraries/python)
        simple_path = parsed.path.rstrip("/")
        # Extract repo name from path (first segment, e.g., trusted-libraries)
        path_parts = [p for p in parsed.path.split("/") if p]
        repo_name = path_parts[0] if path_parts else None
        return base_url, simple_path, repo_name, unquote(parsed.username), unquote(parsed.password)

    return full_url, None, None, None, None


def get_requests_auth() -> Optional[tuple[str, str]]:
    """Get authentication tuple for requests library."""
    base_url, simple_path, repo_name, username, password = get_index_config()
    if username and password:
        return (username, password)
    return None


# =============================================================================
# STEP 1: Get installed package information
# =============================================================================

def get_installed_package_info(package_name: str) -> tuple[str, str, Path]:
    """
    Retrieve metadata about an installed package.
    
    Args:
        package_name: Name of the installed package
        
    Returns:
        Tuple of (package_name, version, install_location)
        
    Raises:
        PackageNotFoundError: If package is not installed
    """
    dist = distribution(package_name)
    version = dist.version
    
    # Get the location of the dist-info directory
    # dist.files[0].locate() gives us a path we can work backwards from
    if dist.files:
        sample_file = dist.files[0].locate()
        # The install location is typically the site-packages directory
        install_location = sample_file.parent
        while install_location.name != "site-packages" and install_location.parent != install_location:
            install_location = install_location.parent
    else:
        install_location = Path("unknown")
    
    return dist.name, version, install_location


# =============================================================================
# STEP 2: Find or download the wheel file
# =============================================================================

def find_wheel_in_cache(package_name: str, version: str) -> Optional[Path]:
    """
    Attempt to find the package's wheel in pip's cache.
    
    Pip caches downloaded wheels, but the cache structure uses hashed paths,
    making it non-trivial to locate a specific wheel. We use pip's cache
    command to find it.
    
    Args:
        package_name: Name of the package
        version: Version string
        
    Returns:
        Path to cached wheel if found, None otherwise
    """
    try:
        result = subprocess.run(
            ["pip", "cache", "list", package_name],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse pip cache output to find matching version
        # Output format: "Cache contents:\n  - <wheel_path>"
        for line in result.stdout.splitlines():
            # Look for lines containing the wheel filename pattern
            # Example: package_name-1.0.0-py3-none-any.whl
            if f"{package_name.replace('-', '_')}-{version}" in line.replace("-", "_"):
                # Extract the path (pip cache list shows paths)
                match = re.search(r"(/[^\s]+\.whl)", line)
                if match:
                    wheel_path = Path(match.group(1))
                    if wheel_path.exists():
                        return wheel_path
                        
    except subprocess.CalledProcessError:
        pass
    
    return None


def download_wheel(package_name: str, version: str, dest_dir: Path) -> Path:
    """
    Download a specific version of a package wheel without installing it.
    
    Uses pip download with --no-deps to get just the wheel file.
    
    Args:
        package_name: Name of the package
        version: Exact version to download
        dest_dir: Directory to download the wheel into
        
    Returns:
        Path to the downloaded wheel file
        
    Raises:
        RuntimeError: If download fails or wheel not found
    """
    print(f"  Downloading {package_name}=={version}...")
    
    result = subprocess.run(
        [
            "pip", "download",
            "--no-deps",  # Don't download dependencies
            "--no-cache-dir",  # Ensure fresh download for verification
            f"{package_name}=={version}",
            "-d", str(dest_dir)
        ],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"Failed to download wheel: {result.stderr}")
    
    # Find the downloaded wheel (could be .whl or .tar.gz for sdist)
    wheels = list(dest_dir.glob("*.whl"))
    if wheels:
        return wheels[0]
    
    # Check for source distribution if no wheel available
    sdists = list(dest_dir.glob("*.tar.gz"))
    if sdists:
        print("  Warning: Only source distribution available, not a wheel")
        return sdists[0]
    
    raise RuntimeError("No wheel or sdist found after download")


def get_wheel_for_package(package_name: str, version: str) -> tuple[Path, bool]:
    """
    Get the wheel file for a package, either from cache or by downloading.
    
    Args:
        package_name: Name of the package
        version: Version string
        
    Returns:
        Tuple of (wheel_path, is_temporary) - is_temporary indicates if
        the caller should clean up the file/directory
    """
    print(f"[1/5] Locating wheel for {package_name}=={version}")
    
    # First, try to find it in pip's cache
    cached_wheel = find_wheel_in_cache(package_name, version)
    if cached_wheel:
        print(f"  Found in cache: {cached_wheel}")
        return cached_wheel, False
    
    # Not in cache, need to download
    print("  Not found in cache, downloading...")
    temp_dir = Path(tempfile.mkdtemp(prefix="pip_verify_"))
    wheel_path = download_wheel(package_name, version, temp_dir)
    print(f"  Downloaded to: {wheel_path}")
    
    return wheel_path, True


# =============================================================================
# STEP 3: Compute wheel hash
# =============================================================================

def compute_sha256(file_path: Path) -> str:
    """
    Compute the SHA256 hash of a file.
    
    Reads file in chunks to handle large files efficiently.
    
    Args:
        file_path: Path to the file to hash
        
    Returns:
        Lowercase hexadecimal SHA256 digest
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read in 64KB chunks for memory efficiency
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


# =============================================================================
# STEP 4: Fetch attestation from Red Hat Trusted Libraries
# =============================================================================

def fetch_attestation(package_name: str, version: str, filename: str) -> Optional[dict]:
    """
    Fetch attestation from Red Hat Trusted Libraries (Pulp) for a specific release file.

    The attestation contains an in-toto SLSA provenance statement with the subject
    (file) and its digest.

    Args:
        package_name: Name of the package
        version: Version string
        filename: The specific wheel/sdist filename

    Returns:
        Attestation dict if available, None otherwise
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not repo_name:
        print("  Warning: Could not get index configuration from pip config")
        return None

    # Red Hat Trusted Libraries integrity API endpoint
    # Format: /api/pypi/{repo_name}/main/integrity/{package}/{version}/{filename}/provenance/
    attestation_url = f"{base_url}/api/pypi/{repo_name}/main/integrity/{package_name}/{version}/{filename}/provenance/"

    try:
        auth = (username, password) if username and password else None
        resp = requests.get(attestation_url, auth=auth, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            print(f"  No attestation found at: {attestation_url}")
            return None
        else:
            print(f"  Warning: Attestation request returned {resp.status_code}")
            return None
    except requests.RequestException as e:
        print(f"  Warning: Failed to fetch attestation: {e}")
        return None


def get_index_digests(package_name: str, version: str, filename: str) -> Optional[dict]:
    """
    Get the published digests for a release file from Red Hat Trusted Libraries.

    Uses the PEP 691 JSON simple API to fetch package metadata including
    file hashes and provenance URLs.

    Args:
        package_name: Name of the package
        version: Version string
        filename: The specific wheel/sdist filename (can be None to get all)

    Returns:
        Dict with 'filename', 'sha256', 'provenance_url', and 'url'
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("  Warning: Could not get index configuration from pip config")
        return None

    # Use the simple index API with JSON accept header
    # simple_path already contains the full path (e.g., /trusted-libraries/python)
    url = f"{base_url}{simple_path}/{package_name}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"  Warning: Failed to fetch index metadata: {e}")
        return None

    # Find matching file or return first wheel matching the version
    for release_file in data.get("files", []):
        release_filename = release_file.get("filename", "")

        # Check if this file matches the requested version
        if version not in release_filename:
            continue

        # If filename specified, match it; otherwise prefer wheels
        if filename and release_filename == filename:
            return {
                "filename": release_filename,
                "sha256": release_file.get("hashes", {}).get("sha256"),
                "provenance_url": release_file.get("provenance"),
                "url": release_file.get("url")
            }
        elif not filename and release_filename.endswith(".whl"):
            return {
                "filename": release_filename,
                "sha256": release_file.get("hashes", {}).get("sha256"),
                "provenance_url": release_file.get("provenance"),
                "url": release_file.get("url")
            }

    # Return first file matching version if no wheel found
    for release_file in data.get("files", []):
        if version in release_file.get("filename", ""):
            return {
                "filename": release_file.get("filename"),
                "sha256": release_file.get("hashes", {}).get("sha256"),
                "provenance_url": release_file.get("provenance"),
                "url": release_file.get("url")
            }

    return None


def extract_attestation_digest(attestation: dict) -> Optional[str]:
    """
    Extract the SHA256 digest from an in-toto attestation statement.

    Red Hat Trusted Libraries attestations follow the in-toto statement format:
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": "package-1.0.0-py3-none-any.whl",
                "digest": {"sha256": "abc123..."}
            }
        ],
        ...
    }

    The attestation is wrapped in a bundle structure with base64-encoded statement.

    Args:
        attestation: The attestation dict

    Returns:
        SHA256 hex digest if found, None otherwise
    """
    statement = attestation

    # Red Hat Trusted Libraries format: attestation_bundles -> attestations -> envelope -> statement
    if "attestation_bundles" in attestation:
        bundles = attestation["attestation_bundles"]
        if bundles and len(bundles) > 0:
            bundle = bundles[0]
            if "attestations" in bundle and len(bundle["attestations"]) > 0:
                # The statement is base64-encoded in the envelope
                att = bundle["attestations"][0]
                if "envelope" in att:
                    # Red Hat uses "statement" field (not "payload")
                    encoded_statement = att["envelope"].get("statement", "")
                    try:
                        statement = json.loads(base64.b64decode(encoded_statement))
                    except (json.JSONDecodeError, base64.binascii.Error) as e:
                        print(f"  Warning: Failed to decode attestation statement: {e}")
                        return None

    # Extract subject digest from in-toto statement
    subjects = statement.get("subject", [])
    if subjects and len(subjects) > 0:
        digest = subjects[0].get("digest", {})
        return digest.get("sha256")

    return None


# =============================================================================
# STEP 5: Verify attestation signature using cosign
# =============================================================================

def extract_attestation_envelope(attestation: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Extract the base64-encoded statement and signature from an attestation.

    Args:
        attestation: The attestation dict from the integrity API

    Returns:
        Tuple of (statement_b64, signature_b64) or (None, None) if not found
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
    statement_b64 = envelope.get("statement")
    signature_b64 = envelope.get("signature")

    return statement_b64, signature_b64


def create_dsse_pae(payload: bytes, payload_type: str = "application/vnd.in-toto+json") -> bytes:
    """
    Create DSSE Pre-Authentication Encoding (PAE) for signature verification.

    DSSE PAE format:
        DSSEv1 <type_len> <type> <payload_len> <payload>

    Where spaces are literal space characters (0x20) and lengths are decimal strings.

    Args:
        payload: The payload bytes (decoded statement JSON)
        payload_type: The payload type string

    Returns:
        The PAE bytes ready for signature verification
    """
    type_len = len(payload_type)
    payload_len = len(payload)

    # Construct: "DSSEv1 <type_len> <type> <payload_len> " + payload
    pae_header = f"DSSEv1 {type_len} {payload_type} {payload_len} ".encode("utf-8")
    return pae_header + payload


def verify_attestation_signature(
    attestation: dict,
    public_key_path: Path
) -> tuple[bool, str]:
    """
    Verify the attestation signature using cosign.

    This constructs the DSSE PAE (Pre-Authentication Encoding) and verifies
    the RSA signature over it using the cosign CLI.

    Args:
        attestation: The attestation dict from the integrity API
        public_key_path: Path to the public key file (PEM format)

    Returns:
        Tuple of (success, message)
    """
    # Check if cosign is available
    try:
        result = subprocess.run(
            ["cosign", "version"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False, "cosign not available"
    except FileNotFoundError:
        return False, "cosign not installed"

    # Check public key exists
    if not public_key_path.exists():
        return False, f"Public key not found: {public_key_path}"

    # Extract statement and signature from attestation
    statement_b64, signature_b64 = extract_attestation_envelope(attestation)
    if not statement_b64 or not signature_b64:
        return False, "Could not extract statement/signature from attestation"

    # Decode statement and signature
    try:
        statement_bytes = base64.b64decode(statement_b64)
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        return False, f"Failed to decode base64: {e}"

    # Create DSSE PAE
    pae_bytes = create_dsse_pae(statement_bytes)

    # Write temporary files for cosign
    with tempfile.TemporaryDirectory(prefix="cosign_verify_") as temp_dir:
        temp_path = Path(temp_dir)

        # Write PAE
        pae_file = temp_path / "pae.bin"
        pae_file.write_bytes(pae_bytes)

        # Write signature
        sig_file = temp_path / "signature.bin"
        sig_file.write_bytes(signature_bytes)

        # Clean the public key (extract only PEM portion)
        clean_key_file = temp_path / "clean_key.pub"
        key_content = public_key_path.read_text()
        # Extract PEM block
        pem_match = re.search(
            r"(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
            key_content,
            re.DOTALL
        )
        if pem_match:
            clean_key_file.write_text(pem_match.group(1))
        else:
            # Try using the key as-is
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
            return False, f"Signature verification failed: {error_msg}"


# =============================================================================
# STEP 6: Verify installed files against RECORD from wheel
# =============================================================================

import csv
import zipfile


def parse_wheel_record(wheel_path: Path, package_name: str) -> dict[str, str]:
    """
    Extract and parse the RECORD file from a wheel.

    The RECORD file is a CSV with columns: path, hash, size
    Hash format is "sha256=<base64-urlsafe-encoded-digest>"

    Args:
        wheel_path: Path to the wheel file
        package_name: Name of the package (to find dist-info directory)

    Returns:
        Dict mapping relative file paths to their expected SHA256 hex digests
    """
    records = {}

    with zipfile.ZipFile(wheel_path, "r") as whl:
        # Find the RECORD file (in <package>-<version>.dist-info/RECORD)
        record_files = [n for n in whl.namelist() if n.endswith("/RECORD")]
        if not record_files:
            return records

        record_path = record_files[0]
        dist_info_prefix = record_path.rsplit("/", 1)[0] + "/"

        with whl.open(record_path) as f:
            # RECORD is a CSV file
            reader = csv.reader(line.decode("utf-8") for line in f)
            for row in reader:
                if len(row) < 2:
                    continue
                file_path, hash_spec = row[0], row[1]

                # Skip entries without hashes (RECORD itself, signatures)
                if not hash_spec or not hash_spec.startswith("sha256="):
                    continue

                # Extract the base64-encoded hash and convert to hex
                b64_hash = hash_spec.split("=", 1)[1]
                # Add padding if needed
                padding = 4 - (len(b64_hash) % 4)
                if padding != 4:
                    b64_hash += "=" * padding
                try:
                    hash_bytes = base64.urlsafe_b64decode(b64_hash)
                    hex_hash = hash_bytes.hex()
                    records[file_path] = hex_hash
                except Exception:
                    continue

    return records


def verify_installed_files_against_wheel(
    package_name: str, wheel_path: Path, verbose: bool = False
) -> tuple[int, int, list[str]]:
    """
    Verify that installed files match the hashes in the wheel's RECORD.

    This extracts the RECORD from the original wheel (verified against the
    index) and compares it to the actual installed files. This proves the
    installed files came from the verified wheel, not just that they match
    the on-disk RECORD (which could have been tampered with).

    Args:
        package_name: Name of the installed package
        wheel_path: Path to the verified wheel file
        verbose: If True, print each file as it's verified

    Returns:
        Tuple of (verified_count, total_count, list_of_mismatches)
    """
    # Get the wheel's RECORD
    wheel_records = parse_wheel_record(wheel_path, package_name)

    if not wheel_records:
        return 0, 0, ["Could not extract RECORD from wheel"]

    # Get install location from the distribution
    dist = distribution(package_name)
    if not dist.files:
        return 0, 0, ["No files recorded for this package"]

    # Find the site-packages directory
    sample_file = dist.files[0].locate()
    install_location = sample_file.parent
    while install_location.name != "site-packages" and install_location.parent != install_location:
        install_location = install_location.parent

    verified = 0
    total = len(wheel_records)
    mismatches = []

    for rel_path, expected_hex_hash in wheel_records.items():
        # Construct the full path to the installed file
        full_path = install_location / rel_path

        if not full_path.exists():
            mismatches.append(f"MISSING: {rel_path}")
            if verbose:
                print(f"    ✗ {full_path} (missing)")
            continue

        try:
            # Compute actual hash of installed file
            with open(full_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()

            if actual_hash == expected_hex_hash:
                verified += 1
                if verbose:
                    print(f"    ✓ {full_path}")
            else:
                mismatches.append(f"HASH MISMATCH: {rel_path}")
                mismatches.append(f"  Expected: {expected_hex_hash}")
                mismatches.append(f"  Actual:   {actual_hash}")
                if verbose:
                    print(f"    ✗ {full_path} (hash mismatch)")

        except Exception as e:
            mismatches.append(f"ERROR checking {rel_path}: {e}")

    return verified, total, mismatches


# =============================================================================
# Main verification flow
# =============================================================================

def verify_package(
    package_name: str,
    public_key_path: Optional[Path] = None,
    verbose: bool = False
) -> bool:
    """
    Run the complete provenance verification for a package.

    This verifies:
    1. The installed package exists
    2. The wheel hash matches Red Hat Trusted Libraries's published hash
    3. If attestations exist, they match the wheel hash
    4. If attestations exist and public key provided, verify signature with cosign
    5. Installed files match the RECORD hashes

    Args:
        package_name: Name of the package to verify
        public_key_path: Optional path to public key for signature verification
        verbose: If True, print each file as it's verified

    Returns:
        True if all verifications pass, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"Verifying package: {package_name}")
    print('='*60)
    
    all_passed = True
    temp_dir = None
    
    try:
        # Step 1: Get installed package info
        try:
            name, version, location = get_installed_package_info(package_name)
            print(f"\nInstalled: {name} {version}")
            print(f"Location: {location}")
        except PackageNotFoundError:
            print(f"\n✗ Package '{package_name}' is not installed")
            return False
        
        # Step 2: Get the wheel file
        wheel_path, is_temp = get_wheel_for_package(name, version)
        if is_temp:
            temp_dir = wheel_path.parent
        
        # Step 3: Compute wheel hash
        print(f"\n[2/5] Computing wheel SHA256")
        wheel_hash = compute_sha256(wheel_path)
        print(f"  Wheel: {wheel_path.name}")
        print(f"  SHA256: {wheel_hash}")
        
        # Step 4: Fetch index data and attestation
        print(f"\n[3/5] Fetching Red Hat Trusted Libraries metadata and attestations")
        index_data = get_index_digests(name, version, wheel_path.name)

        if index_data:
            index_hash = index_data.get("sha256")
            print(f"  Index SHA256: {index_hash}")

            # Compare wheel hash to index hash
            if index_hash == wheel_hash:
                print("  ✓ Wheel hash matches published hash")
            else:
                print("  ✗ Wheel hash does NOT match index!")
                print(f"    Local:  {wheel_hash}")
                print(f"    Index:  {index_hash}")
                all_passed = False

            # Check attestations
            provenance_url = index_data.get("provenance_url")
            if provenance_url:
                print(f"\n  Provenance URL found: {provenance_url}")
                attestation = fetch_attestation(name, version, index_data.get("filename"))
                if attestation:
                    att_digest = extract_attestation_digest(attestation)
                    if att_digest:
                        print(f"  Attestation subject SHA256: {att_digest}")
                        if att_digest == wheel_hash:
                            print("  ✓ Attestation matches wheel hash")
                        else:
                            print("  ✗ Attestation does NOT match!")
                            print(f"    Attestation: {att_digest}")
                            print(f"    Wheel:       {wheel_hash}")
                            all_passed = False
                    else:
                        print("  Warning: Could not extract digest from attestation")

                    # Step 4: Verify attestation signature
                    if public_key_path:
                        print(f"\n[4/5] Verifying attestation signature with cosign")
                        print(f"  Public key: {public_key_path}")
                        sig_ok, sig_msg = verify_attestation_signature(attestation, public_key_path)
                        if sig_ok:
                            print(f"  ✓ {sig_msg}")
                        else:
                            print(f"  ✗ {sig_msg}")
                            all_passed = False
                    else:
                        print(f"\n[4/5] Skipping signature verification (no public key provided)")
                else:
                    print("  Warning: Could not fetch attestation")
            else:
                print("  No attestation available for this package")
        else:
            print("  Warning: Could not fetch index metadata")
            all_passed = False

        # Step 5: Verify installed files against the wheel's RECORD
        print(f"\n[5/5] Verifying installed files against wheel's RECORD")
        print(f"  (Using RECORD from verified wheel, not from disk)")
        verified, total, mismatches = verify_installed_files_against_wheel(
            package_name, wheel_path, verbose=verbose
        )

        print(f"  Files verified: {verified}/{total}")

        if mismatches:
            print("  ✗ Some files failed verification:")
            for m in mismatches[:10]:  # Limit output
                print(f"    - {m}")
            if len(mismatches) > 10:
                print(f"    ... and {len(mismatches) - 10} more")
            all_passed = False
        else:
            print("  ✓ All installed files match wheel's RECORD")
        
        # Summary
        print(f"\n{'='*60}")
        if all_passed:
            print(f"✓ VERIFICATION PASSED for {name} {version}")
        else:
            print(f"✗ VERIFICATION FAILED for {name} {version}")
        print('='*60)
        
        return all_passed
        
    finally:
        # Cleanup temporary download directory
        if temp_dir and temp_dir.exists():
            import shutil
            shutil.rmtree(temp_dir)


def get_default_public_key_path() -> Path:
    """Get the default public key path (redhat-release3.pub in script directory)."""
    script_dir = Path(__file__).parent.resolve()
    return script_dir / "redhat-release3.pub"


def main():
    parser = argparse.ArgumentParser(
        description="Verify Python package provenance against Red Hat Trusted Libraries attestations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s requests                              # Verify with default key
  %(prog)s --public-key /path/to/key.pub requests  # Use custom key
  %(prog)s --no-signature requests               # Skip signature verification
  %(prog)s numpy pandas                          # Verify multiple packages

This tool verifies:
  1. Your installed wheel matches what Red Hat Trusted Libraries has published
  2. If attestations exist, they match the wheel
  3. If public key is provided, attestation signature is verified with cosign
  4. Installed files haven't been modified since installation

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
      For signature verification, cosign CLI must be installed.
        """
    )
    parser.add_argument(
        "packages",
        nargs="+",
        help="Package name(s) to verify"
    )
    parser.add_argument(
        "--public-key", "-k",
        type=Path,
        default=None,
        help="Path to public key for signature verification (default: redhat-release3.pub in script directory)"
    )
    parser.add_argument(
        "--no-signature",
        action="store_true",
        help="Skip attestation signature verification"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print each file path as it's verified against the RECORD"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show final result"
    )

    args = parser.parse_args()

    # Determine public key path
    if args.no_signature:
        public_key_path = None
    elif args.public_key:
        public_key_path = args.public_key.resolve()
    else:
        # Use default key if it exists
        default_key = get_default_public_key_path()
        if default_key.exists():
            public_key_path = default_key
        else:
            print(f"Note: Default public key not found at {default_key}")
            print("      Signature verification will be skipped.")
            print("      Use --public-key to specify a key, or --no-signature to suppress this message.\n")
            public_key_path = None

    results = {}
    for package in args.packages:
        results[package] = verify_package(package, public_key_path, verbose=args.verbose)
        print()  # Blank line between packages
    
    # Exit with appropriate code
    if all(results.values()):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
