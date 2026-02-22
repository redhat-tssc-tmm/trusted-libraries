# fetch_attestation.py

Fetches and displays a package attestation from Red Hat Trusted Libraries.

## Usage

```bash
python fetch_attestation.py <package_name>
python fetch_attestation.py pyyaml
python fetch_attestation.py numpy
```

## What It Does

This script demonstrates how to fetch a cryptographic attestation for a Python package from the Red Hat Trusted Libraries index (a Pulp-based package index).

### Step 1: Query the Simple API

The script queries the PEP 503/691 Simple API to get package file information:
- Available files (wheels, source distributions)
- File hashes (SHA256)
- Provenance URLs (links to attestations)

```
GET https://packages.redhat.com/trusted-libraries/python/{package}/
Accept: application/vnd.pypi.simple.v1+json
```

### Step 2: Fetch the Attestation

Using the provenance URL from the metadata, the script fetches the attestation from the integrity API:

```
GET https://packages.redhat.com/api/pypi/{repo}/main/integrity/{package}/{version}/{filename}/provenance/
```

### Step 3: Decode and Display

The attestation contains a DSSE envelope with a base64-encoded statement. The script:
1. Displays the **raw attestation JSON** (with base64-encoded statement)
2. Decodes and displays the **in-toto statement**
3. Extracts and highlights **key information** (subject, SHA256, build info)

## Output Example

```
======================================================================
RAW ATTESTATION
======================================================================

{
  "version": 1,
  "attestation_bundles": [
    {
      "publisher": { "prn": "prn:auth.user:111", "kind": "Pulp User" },
      "attestations": [
        {
          "envelope": {
            "signature": "X07BJL7CVejYQo...",
            "statement": "eyJfdHlwZSI6Imh0dHBz..."
          }
        }
      ]
    }
  ]
}

======================================================================
DECODED STATEMENT
======================================================================

{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "pyyaml-6.0.3-0-cp312-cp312-manylinux....whl",
      "digest": { "sha256": "df088c59bcc2fc6a..." }
    }
  ],
  "predicate": {
    "buildType": "https://konflux-ci.dev/PythonWheelBuild@v1",
    "builder": { "id": "https://konflux-ci.dev/calunga" },
    "metadata": { "buildFinishedOn": "2026-02-19T21:51:09Z" }
  }
}

======================================================================
KEY INFORMATION
======================================================================

Subject (the file being attested):
  Name:   pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
  SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

Predicate (build information):
  Type:      https://slsa.dev/provenance/v0.2
  BuildType: https://konflux-ci.dev/PythonWheelBuild@v1
  Builder:   https://konflux-ci.dev/calunga
  Built on:  2026-02-19T21:51:09Z
```

## Key Concepts Explained

### What is an Attestation?

An attestation is a signed statement that provides proof about how a software artifact (like a Python wheel) was built. It follows the [in-toto specification](https://in-toto.io/) and contains:

- **Subject**: The file being attested (wheel name + SHA256 hash)
- **Predicate**: Metadata about the build (who built it, when, how)
- **Signature**: Cryptographic proof the attestation hasn't been tampered with

### Package Name Normalization (PEP 503)

Package names in Python are case-insensitive and treat hyphens, underscores, and periods as equivalent. The script normalizes names to lowercase with hyphens:

```
PyYAML -> pyyaml
my_package -> my-package
Some.Package -> some-package
```

### In-toto Statement Structure

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "package-1.0.0-py3-none-any.whl",
      "digest": { "sha256": "abc123..." }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": { ... }
}
```

## Related Scripts

- [verify_signature.py](verify_signature.md) - Verify the attestation's cryptographic signature
- [verify_wheel_hash.py](verify_wheel_hash.md) - Verify the wheel hash matches the attestation
