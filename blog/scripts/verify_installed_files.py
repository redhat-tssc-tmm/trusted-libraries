#!/usr/bin/env python3
"""
Verify Installed Files Against Wheel's RECORD

This script demonstrates how to verify that the files installed on your system
match the original contents of a wheel file by comparing hashes.

Why verify installed files?
---------------------------
When pip installs a wheel, it extracts the files to your site-packages
directory. After installation, those files could potentially be:
  - Modified by malware or an attacker
  - Corrupted by disk errors
  - Accidentally edited

By comparing the installed files against the hashes recorded in the original
wheel's RECORD file, we can detect any modifications.

Why use the wheel's RECORD, not the installed RECORD?
-----------------------------------------------------
When pip installs a wheel, it also extracts the RECORD file. An attacker who
modifies installed files could also update the RECORD to match. By downloading
the original wheel (which we've verified via attestation), we get the
authentic RECORD that was signed by the package builder.

What is the RECORD file?
------------------------
Every wheel contains a RECORD file in its dist-info directory. It's a CSV
file listing every file in the wheel with its hash and size:

    package/__init__.py,sha256=abc123...,1234
    package/module.py,sha256=def456...,5678
    package-1.0.dist-info/METADATA,sha256=ghi789...,2048
    package-1.0.dist-info/RECORD,,

Note: The RECORD file itself has no hash (it can't hash itself).

The hash format is: sha256=<base64url-encoded-digest>
  - Base64url uses - and _ instead of + and /
  - Padding (=) may be omitted

Usage:
    python verify_installed_files.py <package_name>
    python verify_installed_files.py pyyaml
    python verify_installed_files.py --verbose numpy

Requirements:
    pip install requests
"""

import argparse
import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from importlib.metadata import distribution, PackageNotFoundError
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
# Step 1: Get Information About the Installed Package
# =============================================================================
#
# We use Python's importlib.metadata to find information about an installed
# package, including its version and installation location.
#
# The distribution() function returns a Distribution object with:
#   - name: The package name
#   - version: The installed version
#   - files: List of all installed files
#   - locate_file(): Method to find the actual path of a file


def get_installed_package_info(package_name: str) -> Optional[dict]:
    """
    Get information about an installed package.

    Uses importlib.metadata to query the installed package database.

    Args:
        package_name: Name of the package to look up

    Returns:
        Dict with 'name', 'version', 'location' or None if not installed
    """
    try:
        dist = distribution(package_name)

        # Find the site-packages directory by looking at an installed file
        if dist.files:
            sample_file = dist.files[0].locate()
            install_location = sample_file.parent

            # Walk up to find site-packages
            while install_location.name != "site-packages" and install_location.parent != install_location:
                install_location = install_location.parent
        else:
            install_location = Path("unknown")

        return {
            "name": dist.name,
            "version": dist.version,
            "location": install_location,
        }

    except PackageNotFoundError:
        return None


# =============================================================================
# Step 2: Download the Wheel from the Index
# =============================================================================
#
# We need the original wheel file to extract its RECORD. We download the
# wheel matching the installed version from the package index.


def download_wheel_with_pip(package_name: str, version: str, dest_dir: Path) -> Optional[Path]:
    """
    Download a wheel using pip download.

    Using pip ensures we get the correct wheel for the current platform.
    Pip handles platform detection, ABI compatibility, and wheel selection
    automatically.

    Args:
        package_name: Name of the package
        version: Exact version to download
        dest_dir: Directory to download the wheel into

    Returns:
        Path to the downloaded wheel, or None on error
    """
    result = subprocess.run(
        [
            "pip", "download",
            "--no-deps",           # Don't download dependencies
            "--no-cache-dir",      # Ensure fresh download
            f"{package_name}=={version}",
            "-d", str(dest_dir)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"  Error: pip download failed: {result.stderr}")
        return None

    # Find the downloaded wheel
    wheels = list(dest_dir.glob("*.whl"))
    if wheels:
        return wheels[0]

    print("  Error: No wheel found after download")
    return None


# =============================================================================
# Step 3: Extract and Parse the RECORD File from the Wheel
# =============================================================================
#
# A wheel is a ZIP file. We open it and extract the RECORD file from the
# dist-info directory. The RECORD is a CSV file with these columns:
#
#   path,hash,size
#
# Where:
#   - path: Relative path within the wheel (e.g., "package/module.py")
#   - hash: "sha256=<base64url-digest>" or empty for RECORD itself
#   - size: File size in bytes, or empty
#
# The hash uses base64url encoding (RFC 4648), which is URL-safe:
#   - Uses '-' instead of '+'
#   - Uses '_' instead of '/'
#   - Padding '=' may be omitted


def parse_wheel_record(wheel_path: Path) -> dict[str, str]:
    """
    Extract and parse the RECORD file from a wheel.

    Args:
        wheel_path: Path to the wheel file

    Returns:
        Dict mapping relative file paths to their expected SHA256 hex digests
    """
    records = {}

    with zipfile.ZipFile(wheel_path, "r") as whl:
        # Find the RECORD file
        # It's in the .dist-info directory: <name>-<version>.dist-info/RECORD
        record_files = [name for name in whl.namelist() if name.endswith("/RECORD")]

        if not record_files:
            print("  Error: No RECORD file found in wheel")
            return records

        record_path = record_files[0]
        print(f"  Found RECORD at: {record_path}")

        # Read and parse the RECORD file
        with whl.open(record_path) as f:
            # RECORD is a CSV file, read line by line
            reader = csv.reader(line.decode("utf-8") for line in f)

            for row in reader:
                if len(row) < 2:
                    continue

                file_path = row[0]
                hash_spec = row[1]

                # Skip entries without hashes
                # (RECORD itself and signature files have no hash)
                if not hash_spec or not hash_spec.startswith("sha256="):
                    continue

                # Parse the hash
                # Format: sha256=<base64url-encoded-digest>
                b64_hash = hash_spec.split("=", 1)[1]

                # Base64url may omit padding, add it back
                padding_needed = 4 - (len(b64_hash) % 4)
                if padding_needed != 4:
                    b64_hash += "=" * padding_needed

                try:
                    # Decode base64url to bytes, then to hex
                    hash_bytes = base64.urlsafe_b64decode(b64_hash)
                    hex_hash = hash_bytes.hex()
                    records[file_path] = hex_hash
                except Exception as e:
                    print(f"  Warning: Failed to decode hash for {file_path}: {e}")
                    continue

    return records


# =============================================================================
# Step 4: Verify Installed Files Against RECORD
# =============================================================================
#
# For each file listed in RECORD:
#   1. Find the corresponding installed file on disk
#   2. Compute its SHA256 hash
#   3. Compare with the expected hash from RECORD
#
# If all hashes match, the installed files are authentic.


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def verify_installed_files(
    package_name: str,
    install_location: Path,
    expected_records: dict[str, str],
    verbose: bool = False
) -> tuple[int, int, list[str]]:
    """
    Verify installed files against expected hashes from RECORD.

    Args:
        package_name: Name of the package
        install_location: Path to site-packages directory
        expected_records: Dict mapping relative paths to expected SHA256 hashes
        verbose: If True, print each file as it's verified

    Returns:
        Tuple of (verified_count, total_count, list_of_issues)
    """
    verified = 0
    total = len(expected_records)
    issues = []

    for rel_path, expected_hash in expected_records.items():
        # Construct the full path to the installed file
        full_path = install_location / rel_path

        # Check if file exists
        if not full_path.exists():
            issues.append(f"MISSING: {rel_path}")
            if verbose:
                print(f"    MISSING: {full_path}")
            continue

        # Compute the actual hash
        try:
            actual_hash = compute_file_hash(full_path)
        except Exception as e:
            issues.append(f"ERROR reading {rel_path}: {e}")
            if verbose:
                print(f"    ERROR: {full_path} - {e}")
            continue

        # Compare hashes
        if actual_hash == expected_hash:
            verified += 1
            if verbose:
                print(f"    OK: {full_path}")
        else:
            issues.append(f"MODIFIED: {rel_path}")
            issues.append(f"  Expected: {expected_hash}")
            issues.append(f"  Actual:   {actual_hash}")
            if verbose:
                print(f"    MODIFIED: {full_path}")
                print(f"      Expected: {expected_hash}")
                print(f"      Actual:   {actual_hash}")

    return verified, total, issues


# =============================================================================
# Main Verification Flow
# =============================================================================


def verify_package_files(package_name: str, verbose: bool = False) -> bool:
    """
    Run the complete installed files verification flow.

    Steps:
    1. Get information about the installed package
    2. Download the matching wheel from the index
    3. Extract and parse the RECORD file from the wheel
    4. Verify each installed file against the RECORD hashes

    Args:
        package_name: Name of the package to verify
        verbose: If True, print each file as it's verified

    Returns:
        True if all files verify successfully, False otherwise
    """
    print()
    print("=" * 70)
    print(f"Verifying installed files for: {package_name}")
    print("=" * 70)
    print()

    # Step 1: Get installed package info
    print("Step 1: Getting information about installed package...")
    installed_info = get_installed_package_info(package_name)

    if not installed_info:
        print(f"  Error: Package '{package_name}' is not installed")
        return False

    print(f"  Name:     {installed_info['name']}")
    print(f"  Version:  {installed_info['version']}")
    print(f"  Location: {installed_info['location']}")
    print()

    # Step 2: Download the wheel
    print("Step 2: Downloading original wheel from index...")
    print(f"  Using pip to download {package_name}=={installed_info['version']}...")

    temp_dir = Path(tempfile.mkdtemp(prefix="record_verify_"))

    try:
        wheel_path = download_wheel_with_pip(
            package_name,
            installed_info['version'],
            temp_dir
        )
        if not wheel_path:
            return False

        print(f"  Downloaded: {wheel_path.name}")
        print()

        # Step 3: Parse RECORD from wheel
        print("Step 3: Extracting RECORD from wheel...")
        expected_records = parse_wheel_record(wheel_path)

        if not expected_records:
            print("  Error: Could not extract RECORD from wheel")
            return False

        print(f"  Found {len(expected_records)} files with hashes")
        print()

        # Show a sample of the RECORD entries
        print("  Sample RECORD entries:")
        for i, (path, hash_val) in enumerate(list(expected_records.items())[:3]):
            print(f"    {path}")
            print(f"      sha256={hash_val[:16]}...")
        if len(expected_records) > 3:
            print(f"    ... and {len(expected_records) - 3} more")
        print()

        # Step 4: Verify installed files
        print("Step 4: Verifying installed files against RECORD...")
        print()

        if verbose:
            print("  Checking each file:")

        verified, total, issues = verify_installed_files(
            package_name,
            installed_info['location'],
            expected_records,
            verbose=verbose
        )

        # Print summary
        print()
        print("=" * 70)
        print(f"  Files verified: {verified}/{total}")

        if issues:
            print()
            print("  VERIFICATION FAILED - Issues found:")
            for issue in issues[:10]:
                print(f"    {issue}")
            if len(issues) > 10:
                print(f"    ... and {len(issues) - 10} more issues")
            print()
            print("  This could indicate:")
            print("    - Files were modified after installation")
            print("    - Disk corruption")
            print("    - Potential tampering")
        else:
            print()
            print("  VERIFICATION PASSED")
            print()
            print("  All installed files match the original wheel's RECORD.")
            print("  This confirms the files haven't been modified since installation.")

        print("=" * 70)
        print()

        return len(issues) == 0

    finally:
        # Cleanup
        import shutil
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


# =============================================================================
# Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Verify installed package files against the wheel's RECORD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_installed_files.py pyyaml
  python verify_installed_files.py --verbose numpy

This script demonstrates installed file verification:
1. Finds the installed package and its version
2. Downloads the original wheel from the index
3. Extracts the RECORD file from the wheel
4. Compares each installed file's hash against the RECORD

Why use the wheel's RECORD instead of the installed RECORD?
  - The installed RECORD could be modified by an attacker
  - The wheel's RECORD is part of the signed artifact
  - Combined with wheel hash + signature verification, this proves
    the installed files came from the authentic build

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
        """
    )
    parser.add_argument(
        "package",
        help="Name of the package to verify"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each file as it's verified"
    )

    args = parser.parse_args()

    success = verify_package_files(args.package, args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
