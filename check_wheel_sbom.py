#!/usr/bin/env python3
"""
Wheel SBOM Verification Script

This script checks all wheels on the Red Hat Trusted Libraries index for:
1. Presence of SBOM files (*.spdx.json)
2. Whether the SBOM is listed in the wheel's RECORD with correct hash
3. Whether the RECORD lists an SBOM that is not present in the wheel

Outputs a CSV report with the results.

Requirements:
    pip install requests

Usage:
    python check_wheel_sbom.py
    python check_wheel_sbom.py --output results.csv
"""

import argparse
import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import zipfile
from datetime import datetime
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
# Package Listing
# =============================================================================

def list_packages() -> list[str]:
    """List all packages from the index."""
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("Error: Could not get index configuration from pip config")
        return []

    url = f"{base_url}{simple_path}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "text/html"}
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
        resp.raise_for_status()

        # Parse HTML to extract package names
        packages = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>', resp.text)
        packages = [p.strip("/").split("/")[-1] for p in packages if p and not p.startswith("..")]
        return sorted(set(packages))

    except requests.RequestException as e:
        print(f"Error: Failed to list packages: {e}")
        return []


def get_package_wheels(package_name: str) -> list[dict]:
    """Get all wheel files for a package."""
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        return []

    url = f"{base_url}{simple_path}/{package_name}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)

        if resp.status_code == 404:
            return []

        resp.raise_for_status()
        data = resp.json()

        wheels = []
        for file_info in data.get("files", []):
            filename = file_info.get("filename", "")
            if filename.endswith(".whl"):
                wheels.append({
                    "filename": filename,
                    "url": file_info.get("url"),
                    "sha256": file_info.get("hashes", {}).get("sha256")
                })

        return wheels

    except requests.RequestException as e:
        print(f"  Warning: Failed to get wheels for {package_name}: {e}")
        return []


# =============================================================================
# Wheel Download and Inspection
# =============================================================================

def download_wheel(url: str) -> Optional[bytes]:
    """Download a wheel file and return its contents."""
    base_url, simple_path, repo_name, username, password = get_index_config()

    try:
        auth = (username, password) if username and password else None
        resp = requests.get(url, auth=auth, timeout=120)
        resp.raise_for_status()
        return resp.content

    except requests.RequestException as e:
        print(f"  Warning: Failed to download wheel: {e}")
        return None


def parse_record(record_content: str) -> dict[str, Optional[str]]:
    """
    Parse RECORD file content.

    Returns:
        Dict mapping file paths to their SHA256 hash (or None if no hash)
    """
    records = {}

    for line in record_content.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split(",")
        if len(parts) >= 2:
            file_path = parts[0]
            hash_spec = parts[1] if len(parts) > 1 else ""

            if hash_spec.startswith("sha256="):
                # Convert base64 hash to hex
                b64_hash = hash_spec.split("=", 1)[1]
                # Add padding if needed
                padding = 4 - (len(b64_hash) % 4)
                if padding != 4:
                    b64_hash += "=" * padding
                try:
                    hash_bytes = base64.urlsafe_b64decode(b64_hash)
                    records[file_path] = hash_bytes.hex()
                except Exception:
                    records[file_path] = None
            else:
                records[file_path] = None

    return records


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def check_wheel_sbom(wheel_content: bytes) -> dict:
    """
    Check a wheel for SBOM files and RECORD consistency.

    Returns:
        Dict with check results:
        - sbom_files: List of SBOM files found in wheel
        - sbom_in_record: List of SBOM files listed in RECORD
        - sbom_present_and_valid: List of SBOMs present with valid hash
        - sbom_present_hash_mismatch: List of SBOMs present but hash doesn't match
        - sbom_in_record_not_present: List of SBOMs in RECORD but not in wheel
        - sbom_present_not_in_record: List of SBOMs in wheel but not in RECORD
    """
    result = {
        "sbom_files": [],
        "sbom_in_record": [],
        "sbom_present_and_valid": [],
        "sbom_present_hash_mismatch": [],
        "sbom_in_record_not_present": [],
        "sbom_present_not_in_record": [],
        "error": None
    }

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_content)) as whl:
            # Get all files in the wheel
            all_files = whl.namelist()

            # Find SBOM files (*.spdx.json)
            sbom_files = [f for f in all_files if f.endswith(".spdx.json")]
            result["sbom_files"] = sbom_files

            # Find and parse RECORD
            record_files = [f for f in all_files if f.endswith("/RECORD")]
            if not record_files:
                result["error"] = "No RECORD file found"
                return result

            record_path = record_files[0]
            record_content = whl.read(record_path).decode("utf-8")
            records = parse_record(record_content)

            # Find SBOM entries in RECORD
            sbom_in_record = [f for f in records.keys() if f.endswith(".spdx.json")]
            result["sbom_in_record"] = sbom_in_record

            # Check each SBOM file in the wheel
            for sbom_file in sbom_files:
                if sbom_file in records:
                    expected_hash = records[sbom_file]
                    if expected_hash:
                        # Compute actual hash
                        actual_hash = compute_sha256(whl.read(sbom_file))
                        if actual_hash == expected_hash:
                            result["sbom_present_and_valid"].append(sbom_file)
                        else:
                            result["sbom_present_hash_mismatch"].append(sbom_file)
                    else:
                        # No hash in RECORD (unusual)
                        result["sbom_present_and_valid"].append(sbom_file)
                else:
                    result["sbom_present_not_in_record"].append(sbom_file)

            # Check for SBOMs in RECORD but not in wheel
            for sbom_record in sbom_in_record:
                if sbom_record not in sbom_files:
                    result["sbom_in_record_not_present"].append(sbom_record)

    except zipfile.BadZipFile:
        result["error"] = "Invalid wheel file (not a valid ZIP)"
    except Exception as e:
        result["error"] = str(e)

    return result


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check all wheels on the index for SBOM presence and RECORD consistency",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script checks each wheel for:
  1. Presence of SBOM files (*.spdx.json)
  2. Whether the SBOM is listed in RECORD with correct hash
  3. Whether RECORD lists an SBOM that is not in the wheel

Output CSV columns:
  - package: Package name
  - wheel: Wheel filename
  - has_sbom: Whether the wheel contains any SBOM file
  - sbom_count: Number of SBOM files found
  - sbom_files: List of SBOM files in wheel
  - sbom_valid: Number of SBOMs with valid RECORD hash
  - sbom_hash_mismatch: Number of SBOMs with hash mismatch
  - sbom_missing_from_wheel: SBOMs in RECORD but not in wheel
  - sbom_missing_from_record: SBOMs in wheel but not in RECORD
  - status: OK, WARNING, or ERROR
  - error: Error message if any
        """
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("sbom_report.csv"),
        help="Output CSV file path (default: sbom_report.csv)"
    )
    parser.add_argument(
        "--package", "-p",
        type=str,
        default=None,
        help="Check only a specific package (for testing)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Wheel SBOM Verification")
    print("=" * 60)
    print()
    print(f"Output file: {args.output}")
    print()

    # Get packages
    if args.package:
        packages = [args.package]
        print(f"Checking single package: {args.package}")
    else:
        print("Listing packages from index...")
        packages = list_packages()
        print(f"Found {len(packages)} packages")

    print()

    # Prepare CSV
    csv_rows = []
    summary = {
        "total_wheels": 0,
        "wheels_with_sbom": 0,
        "wheels_without_sbom": 0,
        "sbom_valid": 0,
        "sbom_hash_mismatch": 0,
        "sbom_missing_from_wheel": 0,
        "sbom_missing_from_record": 0,
        "errors": 0
    }

    # Process each package
    for i, package in enumerate(packages, 1):
        print(f"[{i}/{len(packages)}] {package}...", end=" ", flush=True)

        wheels = get_package_wheels(package)
        if not wheels:
            print("no wheels")
            continue

        print(f"{len(wheels)} wheel(s)")

        for wheel_info in wheels:
            filename = wheel_info["filename"]
            url = wheel_info["url"]

            # Download wheel
            wheel_content = download_wheel(url)
            if not wheel_content:
                csv_rows.append({
                    "package": package,
                    "wheel": filename,
                    "has_sbom": "",
                    "sbom_count": 0,
                    "sbom_files": "",
                    "sbom_valid": 0,
                    "sbom_hash_mismatch": 0,
                    "sbom_missing_from_wheel": "",
                    "sbom_missing_from_record": "",
                    "status": "ERROR",
                    "error": "Failed to download"
                })
                summary["errors"] += 1
                continue

            # Check SBOM
            result = check_wheel_sbom(wheel_content)
            summary["total_wheels"] += 1

            # Determine status
            if result["error"]:
                status = "ERROR"
                summary["errors"] += 1
            elif result["sbom_present_hash_mismatch"] or result["sbom_in_record_not_present"]:
                status = "WARNING"
            elif result["sbom_files"]:
                status = "OK"
                summary["wheels_with_sbom"] += 1
            else:
                status = "NO_SBOM"
                summary["wheels_without_sbom"] += 1

            # Update summary counts
            summary["sbom_valid"] += len(result["sbom_present_and_valid"])
            summary["sbom_hash_mismatch"] += len(result["sbom_present_hash_mismatch"])
            summary["sbom_missing_from_wheel"] += len(result["sbom_in_record_not_present"])
            summary["sbom_missing_from_record"] += len(result["sbom_present_not_in_record"])

            csv_rows.append({
                "package": package,
                "wheel": filename,
                "has_sbom": "Yes" if result["sbom_files"] else "No",
                "sbom_count": len(result["sbom_files"]),
                "sbom_files": "; ".join(result["sbom_files"]),
                "sbom_valid": len(result["sbom_present_and_valid"]),
                "sbom_hash_mismatch": len(result["sbom_present_hash_mismatch"]),
                "sbom_missing_from_wheel": "; ".join(result["sbom_in_record_not_present"]),
                "sbom_missing_from_record": "; ".join(result["sbom_present_not_in_record"]),
                "status": status,
                "error": result["error"] or ""
            })

    # Write CSV
    print()
    print(f"Writing report to {args.output}...")

    with open(args.output, "w", newline="") as f:
        fieldnames = [
            "package", "wheel", "has_sbom", "sbom_count", "sbom_files",
            "sbom_valid", "sbom_hash_mismatch", "sbom_missing_from_wheel",
            "sbom_missing_from_record", "status", "error"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    # Print summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print()
    print(f"Total wheels checked:      {summary['total_wheels']}")
    print(f"Wheels with SBOM:          {summary['wheels_with_sbom']}")
    print(f"Wheels without SBOM:       {summary['wheels_without_sbom']}")
    print(f"SBOMs valid (hash OK):     {summary['sbom_valid']}")
    print(f"SBOMs hash mismatch:       {summary['sbom_hash_mismatch']}")
    print(f"SBOMs missing from wheel:  {summary['sbom_missing_from_wheel']}")
    print(f"SBOMs missing from RECORD: {summary['sbom_missing_from_record']}")
    print(f"Errors:                    {summary['errors']}")
    print()
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
