#!/usr/bin/env python3
"""
Check Attestation Availability

This script quickly checks all packages on the index to determine
which have attestations available (provenance URLs in metadata).

Requirements:
    pip install requests

Usage:
    python check_attestations.py
    python check_attestations.py --output attestation_report.csv
"""

import argparse
import csv
import re
import subprocess
import sys
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

        packages = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>', resp.text)
        packages = [p.strip("/").split("/")[-1] for p in packages if p and not p.startswith("..")]
        return sorted(set(packages))

    except requests.RequestException as e:
        print(f"Error: Failed to list packages: {e}")
        return []


def get_package_files(package_name: str) -> list[dict]:
    """Get all files for a package with their attestation status."""
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

        files = []
        for file_info in data.get("files", []):
            filename = file_info.get("filename", "")
            files.append({
                "filename": filename,
                "is_wheel": filename.endswith(".whl"),
                "has_attestation": file_info.get("provenance") is not None,
                "provenance_url": file_info.get("provenance"),
                "sha256": file_info.get("hashes", {}).get("sha256")
            })

        return files

    except requests.RequestException as e:
        print(f"  Warning: Failed to get files for {package_name}: {e}")
        return []


def extract_version_from_filename(filename: str) -> str:
    """Extract version from wheel or sdist filename."""
    # Wheel: package-version-...-any.whl
    # Sdist: package-version.tar.gz
    if filename.endswith(".whl"):
        parts = filename.split("-")
        if len(parts) >= 2:
            return parts[1]
    elif filename.endswith(".tar.gz"):
        # Remove .tar.gz and split
        base = filename[:-7]
        parts = base.rsplit("-", 1)
        if len(parts) == 2:
            return parts[1]
    return "unknown"


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check attestation availability for all packages on the index",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script checks package metadata to determine which packages
have attestations (provenance URLs) available.

Output CSV columns:
  - package: Package name
  - filename: File name (wheel or sdist)
  - version: Extracted version
  - is_wheel: Whether the file is a wheel
  - has_attestation: Whether attestation is available
  - provenance_url: The provenance URL if available
        """
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("attestation_report.csv"),
        help="Output CSV file path (default: attestation_report.csv)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Attestation Availability Check")
    print("=" * 60)
    print()
    print(f"Output file: {args.output}")
    print()

    # Get packages
    print("Listing packages from index...")
    packages = list_packages()
    print(f"Found {len(packages)} packages")
    print()

    # Statistics
    summary = {
        "total_packages": len(packages),
        "packages_with_attestation": 0,
        "packages_without_attestation": 0,
        "total_wheels": 0,
        "wheels_with_attestation": 0,
        "wheels_without_attestation": 0,
    }

    csv_rows = []
    packages_without_attestation = []

    # Process each package
    for i, package in enumerate(packages, 1):
        print(f"[{i}/{len(packages)}] {package}...", end=" ", flush=True)

        files = get_package_files(package)
        if not files:
            print("no files")
            continue

        wheels = [f for f in files if f["is_wheel"]]
        wheels_with_att = [f for f in wheels if f["has_attestation"]]

        summary["total_wheels"] += len(wheels)
        summary["wheels_with_attestation"] += len(wheels_with_att)
        summary["wheels_without_attestation"] += len(wheels) - len(wheels_with_att)

        if wheels_with_att:
            summary["packages_with_attestation"] += 1
            print(f"{len(wheels)} wheel(s), {len(wheels_with_att)} with attestation")
        else:
            summary["packages_without_attestation"] += 1
            packages_without_attestation.append(package)
            print(f"{len(wheels)} wheel(s), NO attestation")

        for file_info in files:
            csv_rows.append({
                "package": package,
                "filename": file_info["filename"],
                "version": extract_version_from_filename(file_info["filename"]),
                "is_wheel": "Yes" if file_info["is_wheel"] else "No",
                "has_attestation": "Yes" if file_info["has_attestation"] else "No",
                "provenance_url": file_info["provenance_url"] or ""
            })

    # Write CSV
    print()
    print(f"Writing report to {args.output}...")

    with open(args.output, "w", newline="") as f:
        fieldnames = ["package", "filename", "version", "is_wheel", "has_attestation", "provenance_url"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    # Print summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print()
    print(f"Total packages:              {summary['total_packages']}")
    print(f"Packages with attestation:   {summary['packages_with_attestation']}")
    print(f"Packages without attestation: {summary['packages_without_attestation']}")
    print()
    print(f"Total wheels:                {summary['total_wheels']}")
    print(f"Wheels with attestation:     {summary['wheels_with_attestation']}")
    print(f"Wheels without attestation:  {summary['wheels_without_attestation']}")
    print()

    if packages_without_attestation:
        print("Packages WITHOUT attestation:")
        for pkg in packages_without_attestation:
            print(f"  - {pkg}")
        print()

    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
