#!/usr/bin/env python3
"""
Extract SBOM files from all wheels on the index.

This script downloads all wheels from the Red Hat Trusted Libraries index
and extracts any SBOM files (*.spdx.json) to a specified directory.

Requirements:
    pip install requests

Usage:
    python extract_sboms.py
    python extract_sboms.py --output ../sboms
"""

import argparse
import io
import re
import subprocess
import sys
import zipfile
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
# Wheel Download and SBOM Extraction
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
        print(f"    Warning: Failed to download wheel: {e}")
        return None


def extract_sboms_from_wheel(wheel_content: bytes, wheel_filename: str, output_dir: Path) -> list[str]:
    """
    Extract SBOM files from a wheel.

    Args:
        wheel_content: The wheel file content
        wheel_filename: Original wheel filename (for naming)
        output_dir: Directory to save extracted SBOMs

    Returns:
        List of extracted SBOM filenames
    """
    extracted = []

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_content)) as whl:
            for name in whl.namelist():
                if name.endswith(".spdx.json"):
                    # Extract the SBOM
                    sbom_content = whl.read(name)

                    # Create output filename: wheel_name + sbom_basename
                    # e.g., urllib3-2.6.3-0-py3-none-any.whl -> urllib3-2.6.3-0.spdx.json
                    sbom_basename = Path(name).name
                    output_path = output_dir / sbom_basename

                    # Handle potential conflicts by adding wheel info
                    if output_path.exists():
                        # Add more context to filename
                        wheel_base = wheel_filename.replace(".whl", "")
                        output_path = output_dir / f"{wheel_base}.spdx.json"

                    output_path.write_bytes(sbom_content)
                    extracted.append(str(output_path.name))

    except zipfile.BadZipFile:
        print(f"    Warning: Invalid wheel file")
    except Exception as e:
        print(f"    Warning: Error extracting SBOMs: {e}")

    return extracted


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Extract SBOM files from all wheels on the index",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script downloads all wheels and extracts any SBOM files (*.spdx.json).

Example:
  python extract_sboms.py                  # Extract to ../sboms
  python extract_sboms.py --output ./sboms  # Extract to custom directory
        """
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("../sboms"),
        help="Output directory for SBOM files (default: ../sboms)"
    )
    parser.add_argument(
        "--package", "-p",
        type=str,
        default=None,
        help="Extract from a specific package only (for testing)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SBOM Extraction")
    print("=" * 60)
    print()

    # Create output directory
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")
    print()

    # Get packages
    if args.package:
        packages = [args.package]
        print(f"Extracting from single package: {args.package}")
    else:
        print("Listing packages from index...")
        packages = list_packages()
        print(f"Found {len(packages)} packages")

    print()

    # Statistics
    total_wheels = 0
    total_sboms = 0
    all_sboms = []

    # Process each package
    for i, package in enumerate(packages, 1):
        print(f"[{i}/{len(packages)}] {package}...", end=" ", flush=True)

        wheels = get_package_wheels(package)
        if not wheels:
            print("no wheels")
            continue

        package_sboms = 0
        for wheel_info in wheels:
            filename = wheel_info["filename"]
            url = wheel_info["url"]

            # Download wheel
            wheel_content = download_wheel(url)
            if not wheel_content:
                continue

            total_wheels += 1

            # Extract SBOMs
            extracted = extract_sboms_from_wheel(wheel_content, filename, output_dir)
            package_sboms += len(extracted)
            total_sboms += len(extracted)
            all_sboms.extend(extracted)

        print(f"{len(wheels)} wheel(s), {package_sboms} SBOM(s)")

    # Summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print()
    print(f"Total wheels processed: {total_wheels}")
    print(f"Total SBOMs extracted:  {total_sboms}")
    print(f"Output directory:       {output_dir}")
    print()

    if all_sboms:
        print("Extracted files:")
        for sbom in sorted(all_sboms)[:20]:
            print(f"  - {sbom}")
        if len(all_sboms) > 20:
            print(f"  ... and {len(all_sboms) - 20} more")


if __name__ == "__main__":
    main()
