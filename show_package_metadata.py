#!/usr/bin/env python3
"""
Show Package Metadata from the Simple API

Fetches and displays all metadata fields returned by the PEP 691 JSON
Simple API for a given package.

Usage:
    python show_package_metadata.py
    python show_package_metadata.py requests
    python show_package_metadata.py --raw numpy
"""

import argparse
import json
import re
import subprocess
import sys
from typing import Optional
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


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
    """Normalize a package name per PEP 503."""
    return re.sub(r'[-_.]+', '-', name).lower()


def fetch_simple_api_metadata(package_name: str) -> tuple[Optional[str], Optional[dict]]:
    """
    Fetch all metadata for a package from the PEP 691 JSON Simple API.

    Args:
        package_name: Name of the package

    Returns:
        Tuple of (url, data) where url is the API URL queried and data is
        the full JSON response dict, or (None, None) on error
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("Error: Could not get index configuration from pip config")
        return None, None

    normalized_name = normalize_package_name(package_name)
    url = f"{base_url}{simple_path}/{normalized_name}/"

    try:
        auth = (username, password) if username and password else None
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        resp = requests.get(url, auth=auth, headers=headers, timeout=30)
        resp.raise_for_status()
        return url, resp.json()
    except requests.RequestException as e:
        print(f"Error: Failed to fetch metadata for '{package_name}': {e}")
        return url, None


def print_file_entry(file_info: dict, index: int) -> None:
    """Print a single file entry with all its fields."""
    filename = file_info.get("filename", "?")
    print(f"  [{index}] {filename}")

    for key, value in file_info.items():
        if key == "filename":
            continue
        if key == "hashes" and isinstance(value, dict):
            for algo, digest in value.items():
                print(f"       {algo}: {digest}")
        elif value is not None and value != "":
            print(f"       {key}: {value}")


def show_metadata(package_name: str, raw: bool = False) -> None:
    """Fetch and display all Simple API metadata for a package."""
    url, data = fetch_simple_api_metadata(package_name)
    print(f"Fetching metadata for: {package_name}")
    print(f"URL: {url}")
    print(f"Accept: application/vnd.pypi.simple.v1+json")
    print()

    if not data:
        sys.exit(1)

    if raw:
        print(json.dumps(data, indent=2))
        return

    # Top-level fields
    top_level_keys = [k for k in data if k != "files"]
    if top_level_keys:
        print("Package-level fields:")
        for key in top_level_keys:
            value = data[key]
            if isinstance(value, list):
                print(f"  {key}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  {key}: {value}")
        print()

    # Files
    files = data.get("files", [])
    print(f"Files: {len(files)}")
    print()

    for i, file_info in enumerate(files, 1):
        print_file_entry(file_info, i)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Show all Simple API metadata for a package",
    )
    parser.add_argument(
        "package",
        nargs="?",
        default="numpy",
        help="Package name (default: numpy)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print the raw JSON response",
    )

    args = parser.parse_args()
    show_metadata(args.package, raw=args.raw)


if __name__ == "__main__":
    main()
