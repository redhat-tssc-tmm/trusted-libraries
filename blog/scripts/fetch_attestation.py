#!/usr/bin/env python3
"""
Fetch and Display Package Attestation

This script demonstrates how to fetch a cryptographic attestation for a Python
package from Red Hat Trusted Libraries (a Pulp-based package index).

What is an attestation?
-----------------------
An attestation is a signed statement that provides proof about how a software
artifact (like a Python wheel) was built. It follows the in-toto specification
and contains:
  - A "subject": the file being attested (wheel name + SHA256 hash)
  - A "predicate": metadata about the build (who built it, when, how)
  - A cryptographic signature proving the attestation hasn't been tampered with

The attestation is stored as a "DSSE envelope" (Dead Simple Signing Envelope)
where the statement is base64-encoded and accompanied by a signature.

Usage:
    python fetch_attestation.py <package_name>
    python fetch_attestation.py requests
    python fetch_attestation.py numpy

Requirements:
    pip install requests
"""

import argparse
import base64
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


# =============================================================================
# Step 1: Get Index Configuration from pip
# =============================================================================
#
# pip stores its configuration (including the index URL with credentials)
# in a config file. We parse this to get the URL we need to query.
#
# The index URL typically looks like:
#   https://username:password@packages.redhat.com/trusted-libraries/python/
#
# We need to extract:
#   - base_url: https://packages.redhat.com
#   - repo_name: trusted-libraries (for the integrity/attestation API)
#   - credentials: username and password for authentication


def get_index_config() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract index URL and credentials from pip config.

    This runs `pip config list` and parses the output to find the configured
    index URL. The URL contains embedded credentials that we extract.

    Returns:
        Tuple of (base_url, simple_path, repo_name, username, password)
        - base_url: The scheme and hostname (e.g., https://packages.redhat.com)
        - simple_path: Full path to the simple API (e.g., /trusted-libraries/python)
        - repo_name: Repository name for integrity API (e.g., trusted-libraries)
        - username: Authentication username
        - password: Authentication password
    """
    # Run pip config to get the current configuration
    result = subprocess.run(
        ["pip", "config", "list"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None, None, None, None, None

    # Look for the global index-url setting
    # Output format: global.index-url='https://user:pass@host/path/'
    match = re.search(r"global\.index-url='([^']+)'", result.stdout)
    if not match:
        return None, None, None, None, None

    full_url = match.group(1)

    # Parse the URL to extract components
    # urlparse handles URLs like: https://user:pass@host/path/
    parsed = urlparse(full_url)

    if parsed.username and parsed.password:
        # Reconstruct base URL without credentials
        base_url = f"{parsed.scheme}://{parsed.hostname}"

        # The simple API path (e.g., /trusted-libraries/python)
        simple_path = parsed.path.rstrip("/")

        # Extract repository name from path (first segment)
        # /trusted-libraries/python -> trusted-libraries
        path_parts = [p for p in parsed.path.split("/") if p]
        repo_name = path_parts[0] if path_parts else None

        # unquote handles URL-encoded characters in credentials
        return base_url, simple_path, repo_name, unquote(parsed.username), unquote(parsed.password)

    return full_url, None, None, None, None


# =============================================================================
# Step 2: Get Package Information from the Simple API
# =============================================================================
#
# Python package indexes implement PEP 503 (Simple Repository API).
# We use PEP 691's JSON format to get structured data including:
#   - Available files (wheels, source distributions)
#   - File hashes (SHA256)
#   - Provenance URLs (links to attestations)


def normalize_package_name(name: str) -> str:
    """
    Normalize a package name according to PEP 503.

    Package names in Python are case-insensitive and treat hyphens,
    underscores, and periods as equivalent. The canonical form used
    in URLs is lowercase with hyphens.

    Examples:
        PyYAML -> pyyaml
        my_package -> my-package
        Some.Package -> some-package
    """
    return re.sub(r'[-_.]+', '-', name).lower()


def get_package_info(package_name: str) -> Optional[dict]:
    """
    Fetch package information from the Simple API.

    The Simple API (PEP 503/691) provides a JSON response with all available
    files for a package, including their hashes and provenance URLs.

    Args:
        package_name: Name of the package to look up

    Returns:
        Dict with 'filename', 'version', 'sha256', 'provenance_url' for the
        latest wheel, or None if not found
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not simple_path:
        print("Error: Could not get index configuration from pip config")
        return None

    # Construct the Simple API URL for this package
    # Format: {base_url}{simple_path}/{normalized_package_name}/
    normalized_name = normalize_package_name(package_name)
    url = f"{base_url}{simple_path}/{normalized_name}/"

    try:
        # Authenticate if credentials are available
        auth = (username, password) if username and password else None

        # Request JSON format using PEP 691 content negotiation
        # This header tells the server we want structured JSON, not HTML
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}

        response = requests.get(url, auth=auth, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as e:
        print(f"Error: Failed to fetch package info: {e}")
        return None

    # Find the most recent wheel file
    # Wheels are preferred over source distributions (.tar.gz)
    # We look for files ending in .whl
    for file_info in reversed(data.get("files", [])):
        filename = file_info.get("filename", "")
        if filename.endswith(".whl"):
            # Extract version from wheel filename
            # Format: {name}-{version}-{python}-{abi}-{platform}.whl
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


# =============================================================================
# Step 3: Fetch the Attestation from the Integrity API
# =============================================================================
#
# Red Hat Trusted Libraries provides attestations via an "integrity API"
# that's separate from the standard Simple API.
#
# The attestation is returned as a JSON document containing:
#   - attestation_bundles: array of attestation bundles
#     - publisher: who created/signed the attestation
#     - attestations: array of individual attestations
#       - envelope: the DSSE envelope containing:
#         - statement: base64-encoded in-toto statement
#         - signature: base64-encoded cryptographic signature


def fetch_attestation(package_name: str, version: str, filename: str) -> Optional[dict]:
    """
    Fetch the attestation for a specific package file.

    The integrity API provides cryptographic attestations that prove
    the provenance (origin and build process) of each package file.

    Args:
        package_name: Name of the package
        version: Version string
        filename: The specific wheel filename

    Returns:
        The attestation dict if available, None otherwise
    """
    base_url, simple_path, repo_name, username, password = get_index_config()

    if not base_url or not repo_name:
        print("Error: Could not get index configuration")
        return None

    # Construct the integrity API URL
    # Format: /api/pypi/{repo_name}/main/integrity/{package}/{version}/{filename}/provenance/
    normalized_name = normalize_package_name(package_name)
    attestation_url = (
        f"{base_url}/api/pypi/{repo_name}/main/integrity/"
        f"{normalized_name}/{version}/{filename}/provenance/"
    )

    print(f"Fetching attestation from:\n  {attestation_url}\n")

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
# Step 4: Decode and Display the Attestation
# =============================================================================
#
# The attestation contains a base64-encoded "statement" that follows the
# in-toto specification. We decode this to show the actual content.
#
# The statement structure (in-toto v0.1):
# {
#   "_type": "https://in-toto.io/Statement/v0.1",
#   "subject": [
#     {
#       "name": "package-1.0.0-py3-none-any.whl",
#       "digest": {"sha256": "abc123..."}
#     }
#   ],
#   "predicateType": "https://slsa.dev/provenance/v0.2",
#   "predicate": {
#     "buildType": "...",
#     "builder": {"id": "..."},
#     "metadata": {...}
#   }
# }


def decode_attestation_statement(attestation: dict) -> Optional[dict]:
    """
    Extract and decode the statement from an attestation.

    The attestation envelope contains a base64-encoded JSON statement.
    This function extracts and decodes it.

    Args:
        attestation: The raw attestation dict from the API

    Returns:
        The decoded statement as a dict, or None if decoding fails
    """
    # Navigate the attestation structure to find the statement
    # Structure: attestation_bundles[0].attestations[0].envelope.statement
    try:
        bundles = attestation.get("attestation_bundles", [])
        if not bundles:
            return None

        attestations = bundles[0].get("attestations", [])
        if not attestations:
            return None

        envelope = attestations[0].get("envelope", {})
        statement_b64 = envelope.get("statement")

        if not statement_b64:
            return None

        # Decode the base64 string to get the JSON statement
        statement_bytes = base64.b64decode(statement_b64)
        statement = json.loads(statement_bytes)

        return statement

    except (json.JSONDecodeError, base64.binascii.Error, KeyError, IndexError) as e:
        print(f"Warning: Failed to decode statement: {e}")
        return None


def display_attestation(attestation: dict, statement: Optional[dict]) -> None:
    """
    Display the attestation in a readable format.

    Shows both the raw attestation structure and the decoded statement.
    """
    print("=" * 70)
    print("RAW ATTESTATION")
    print("=" * 70)
    print()
    print("This is the attestation as returned by the integrity API.")
    print("Note: The 'statement' field is base64-encoded.")
    print()
    print(json.dumps(attestation, indent=2))
    print()

    if statement:
        print("=" * 70)
        print("DECODED STATEMENT")
        print("=" * 70)
        print()
        print("This is the in-toto statement after base64 decoding.")
        print("It contains the subject (file + hash) and predicate (build info).")
        print()
        print(json.dumps(statement, indent=2))
        print()

        # Highlight key information
        print("=" * 70)
        print("KEY INFORMATION")
        print("=" * 70)
        print()

        # Extract subject info
        subjects = statement.get("subject", [])
        if subjects:
            subject = subjects[0]
            print(f"Subject (the file being attested):")
            print(f"  Name:   {subject.get('name', 'N/A')}")
            print(f"  SHA256: {subject.get('digest', {}).get('sha256', 'N/A')}")
            print()

        # Extract predicate info
        predicate = statement.get("predicate", {})
        if predicate:
            # Handle nested predicate structure
            inner_predicate = predicate.get("predicate", predicate)
            print(f"Predicate (build information):")
            print(f"  Type:      {statement.get('predicateType', 'N/A')}")
            print(f"  BuildType: {inner_predicate.get('buildType', 'N/A')}")

            builder = inner_predicate.get("builder", {})
            print(f"  Builder:   {builder.get('id', 'N/A')}")

            metadata = inner_predicate.get("metadata", {})
            if metadata:
                print(f"  Built on:  {metadata.get('buildFinishedOn', 'N/A')}")


# =============================================================================
# Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and display a package attestation from Red Hat Trusted Libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fetch_attestation.py requests
  python fetch_attestation.py numpy
  python fetch_attestation.py pyyaml

This script demonstrates how attestations work:
1. Queries the Simple API (PEP 503/691) to get package file info
2. Fetches the attestation from the integrity API
3. Decodes and displays the in-toto statement

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
        """
    )
    parser.add_argument(
        "package",
        help="Name of the package to fetch attestation for"
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print(f"Fetching attestation for: {args.package}")
    print("=" * 70)
    print()

    # Step 1: Get package info from the Simple API
    print("Step 1: Querying Simple API for package info...")
    package_info = get_package_info(args.package)

    if not package_info:
        print("Failed to get package information")
        sys.exit(1)

    print(f"  Found: {package_info['filename']}")
    print(f"  Version: {package_info['version']}")
    print(f"  SHA256: {package_info['sha256']}")
    print(f"  Has provenance URL: {'Yes' if package_info['provenance_url'] else 'No'}")
    print()

    # Step 2: Fetch the attestation
    print("Step 2: Fetching attestation from integrity API...")
    attestation = fetch_attestation(
        args.package,
        package_info['version'],
        package_info['filename']
    )

    if not attestation:
        print("Failed to fetch attestation")
        sys.exit(1)

    # Step 3: Decode and display
    print("Step 3: Decoding attestation statement...")
    print()
    statement = decode_attestation_statement(attestation)

    display_attestation(attestation, statement)


if __name__ == "__main__":
    main()
