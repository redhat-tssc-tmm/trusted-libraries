#!/usr/bin/env python3
"""List available packages from a Pulp Python index."""

import argparse
import re
import subprocess
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, unquote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import base64


class SimpleIndexParser(HTMLParser):
    """Parse PEP 503 simple index HTML to extract package links."""

    def __init__(self):
        super().__init__()
        self.packages = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    # Extract package name from href
                    package_name = value.rstrip("/").split("/")[-1]
                    if package_name:
                        self.packages.append(package_name)


def get_credentials_from_pip_config():
    """Extract index URL and credentials from pip config list."""
    result = subprocess.run(
        ["pip", "config", "list"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None, None, None

    # Parse the index-url from pip config output
    match = re.search(r"global\.index-url='([^']+)'", result.stdout)
    if not match:
        return None, None, None

    full_url = match.group(1)

    # Parse URL with embedded credentials: https://user:pass@host/path/
    parsed = urlparse(full_url)

    if parsed.username and parsed.password:
        # Reconstruct URL without credentials
        base_url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
        return base_url, unquote(parsed.username), unquote(parsed.password)

    return full_url, None, None


def fetch_url(url: str, username: str = None, password: str = None) -> str:
    """Fetch URL content with optional basic auth."""
    request = Request(url)
    request.add_header("Accept", "text/html")

    if username and password:
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")

    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def list_packages(index_url: str, username: str = None, password: str = None) -> list:
    """Fetch and parse the simple index to get package names."""
    # The index URL is already the simple index (no /simple/ suffix needed)
    simple_url = index_url.rstrip("/") + "/"

    html = fetch_url(simple_url, username, password)

    parser = SimpleIndexParser()
    parser.feed(html)

    return sorted(set(parser.packages))


def get_package_versions(
    index_url: str, package_name: str, username: str = None, password: str = None
) -> list:
    """Fetch available versions for a specific package."""
    # The index URL is already the simple index (no /simple/ suffix needed)
    simple_url = index_url.rstrip("/") + f"/{package_name}/"

    html = fetch_url(simple_url, username, password)

    # Extract version from wheel/sdist filenames
    versions = set()

    # Normalize package name for matching (PEP 503: replace - and _ with [-_])
    pkg_pattern = re.escape(package_name).replace("_", "[-_]").replace("-", "[-_]")

    # Match wheel files: package-version-...whl
    wheel_pattern = re.compile(rf"{pkg_pattern}-([^-]+)-.*\.whl", re.IGNORECASE)

    # Match sdist files: package-version.tar.gz or .zip
    sdist_pattern = re.compile(rf"{pkg_pattern}-([^-]+)\.(tar\.gz|zip)", re.IGNORECASE)

    for match in wheel_pattern.finditer(html):
        versions.add(match.group(1))

    for match in sdist_pattern.finditer(html):
        versions.add(match.group(1))

    return sorted(versions)


def main():
    parser = argparse.ArgumentParser(
        description="List packages available in a Pulp Python index"
    )
    parser.add_argument(
        "--index-url",
        help="Base URL of the Pulp index (default: from pip config)",
    )
    parser.add_argument(
        "--username",
        help="Username for authentication (default: from pip config)",
    )
    parser.add_argument(
        "--password",
        help="Password for authentication (default: from pip config)",
    )
    parser.add_argument(
        "--package",
        "-p",
        help="Show versions for a specific package instead of listing all packages",
    )
    parser.add_argument(
        "--versions",
        "-v",
        action="store_true",
        help="Show versions for each package (slower, makes one request per package)",
    )

    args = parser.parse_args()

    # Get credentials from pip config if not provided
    pip_url, pip_user, pip_pass = get_credentials_from_pip_config()

    index_url = args.index_url or pip_url
    username = args.username or pip_user
    password = args.password or pip_pass

    if not index_url:
        print("Error: No index URL found. Provide --index-url or configure pip.", file=sys.stderr)
        sys.exit(1)

    try:
        if args.package:
            # Show versions for a specific package
            versions = get_package_versions(index_url, args.package, username, password)
            if versions:
                print(f"{args.package}:")
                for version in versions:
                    print(f"  {version}")
            else:
                print(f"No versions found for {args.package}", file=sys.stderr)
                sys.exit(1)
        else:
            # List all packages
            packages = list_packages(index_url, username, password)

            if args.versions:
                for pkg in packages:
                    try:
                        versions = get_package_versions(index_url, pkg, username, password)
                        print(f"{pkg}: {', '.join(versions)}")
                    except (HTTPError, URLError) as e:
                        print(f"{pkg}: <error fetching versions: {e}>", file=sys.stderr)
            else:
                for pkg in packages:
                    print(pkg)

            print(f"\nTotal: {len(packages)} packages", file=sys.stderr)

    except HTTPError as e:
        print(f"HTTP Error: {e.code} {e.reason}", file=sys.stderr)
        if e.code == 401:
            print("Authentication failed. Check your credentials.", file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
