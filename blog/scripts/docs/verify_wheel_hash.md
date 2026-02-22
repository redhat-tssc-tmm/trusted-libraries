# verify_wheel_hash.py

Verifies that a Python wheel file's SHA256 hash matches the digest recorded in its attestation.

## Usage

```bash
python verify_wheel_hash.py <package_name>
python verify_wheel_hash.py pyyaml
python verify_wheel_hash.py --keep-wheel numpy
```

## Options

- `--keep-wheel`: Keep the downloaded wheel file after verification

## What It Does

This script demonstrates how to verify that a wheel file's hash matches the hash recorded in its attestation. This is the critical link between the cryptographically signed attestation and the actual package file.

### Step 1: Fetch Package Info from Simple API

Gets the wheel's download URL and the published SHA256 hash from the index metadata.

### Step 2: Download the Wheel

Downloads the wheel file from the package index to compute its hash.

### Step 3: Compute SHA256 Hash

Computes the SHA256 hash of the downloaded wheel using chunked reading for memory efficiency:

```python
sha256_hash = hashlib.sha256()
with open(wheel_path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        sha256_hash.update(chunk)
return sha256_hash.hexdigest()
```

### Step 4: Fetch Attestation

Retrieves the attestation from the integrity API.

### Step 5: Extract Digest from Attestation

Decodes the base64 statement and extracts the subject's SHA256 digest:

```json
{
  "subject": [
    {
      "name": "package-1.0.0-py3-none-any.whl",
      "digest": {
        "sha256": "abc123..."  // <-- This is extracted
      }
    }
  ]
}
```

### Step 6: Compare Hashes

Compares the computed hash with the attestation hash. If they match, the wheel is verified.

## Output Example

```
======================================================================
Verifying wheel hash for: pyyaml
======================================================================

Step 1: Fetching package info from Simple API...
  Filename: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
  Version:  6.0.3
  Index SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

Step 2: Downloading wheel from index...
  URL: https://packages.redhat.com/api/pulp-content/...
  Downloaded: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
  Size: 693,677 bytes

Step 3: Computing SHA256 hash of wheel...
  Computed SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

  Comparing with index hash...
    Index hash matches computed hash

Step 4: Fetching attestation from integrity API...
  Attestation retrieved successfully

Step 5: Extracting digest from attestation subject...
  Attestation SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

Step 6: Comparing wheel hash with attestation hash...

======================================================================
  HASH VERIFIED: Wheel matches attestation

  This confirms:
    - The wheel you have is the one that was attested
    - No bytes have been modified since signing
    - Combined with signature verification, this proves provenance
======================================================================
```

## Key Concepts Explained

### Why Verify the Hash?

The attestation cryptographically binds a specific file (identified by its SHA256 hash) to build provenance information. By verifying that:

1. The wheel you have matches the hash in the attestation
2. The attestation signature is valid (see [verify_signature.py](verify_signature.md))

You can be confident that:
- The wheel was built by the claimed builder (Red Hat/Konflux)
- The wheel hasn't been modified since it was signed
- You're not installing a tampered or substituted package

### What is a Wheel?

A wheel (.whl) is Python's binary package format. It's a ZIP file containing:
- The package code (Python files, compiled extensions)
- Metadata (package name, version, dependencies)
- A RECORD file listing all contents with their hashes

**Wheel filename format:**
```
{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl

Example:
numpy-1.24.0-cp311-cp311-manylinux_2_17_x86_64.whl
└────┘ └───┘ └────┘ └────┘ └─────────────────────┘
 name   ver   python  abi        platform
```

### What is SHA256?

SHA256 is a cryptographic hash function that produces a 256-bit (64 hex character) digest. It has these properties:

- **Deterministic**: Same input always produces same output
- **One-way**: Cannot reverse the hash to get the input
- **Collision-resistant**: Infeasible to find two inputs with same hash
- **Avalanche effect**: Small input change = completely different hash

This makes it ideal for verifying file integrity.

### Three Hashes, One Truth

The script shows three hashes that should all match:

1. **Index hash**: From the Simple API metadata (PEP 691)
2. **Computed hash**: Calculated from the downloaded wheel
3. **Attestation hash**: From the signed in-toto statement subject

If all three match, you have strong assurance the wheel is authentic.

## Related Scripts

- [fetch_attestation.py](fetch_attestation.md) - Fetch and display the attestation
- [verify_signature.py](verify_signature.md) - Verify the attestation signature
- [verify_installed_files.py](verify_installed_files.md) - Verify installed files match the wheel
