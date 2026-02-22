# verify_package_provenance.py

Complete end-to-end verification of Python packages from Red Hat Trusted Libraries. This script combines all verification steps into a single tool.

## Usage

```bash
python verify_package_provenance.py <package_name>
python verify_package_provenance.py pyyaml
python verify_package_provenance.py --verbose pyyaml
python verify_package_provenance.py --public-key /path/to/key.pub numpy
python verify_package_provenance.py --no-signature pyyaml
python verify_package_provenance.py pyyaml urllib3 certifi  # Multiple packages
```

## Options

| Option | Description |
|--------|-------------|
| `--public-key`, `-k` | Path to public key file (default: `../../redhat-release3.pub`) |
| `--no-signature` | Skip attestation signature verification |
| `--verbose`, `-v` | Print detailed output including attestation JSON and each verified file |
| `--quiet`, `-q` | Only show final result |

## Requirements

- `pip install requests`
- `cosign` CLI tool ([installation guide](https://docs.sigstore.dev/cosign/system_config/installation/))
- pip configured with Red Hat Trusted Libraries index URL
- Red Hat's public key file (default: `../../redhat-release3.pub`)
  - The `release key 3` key file can be downloaded from [Red Hat's public key site](https://access.redhat.com/security/team/key)

## What It Does

This script performs complete provenance verification in 5 steps:

### Step 1: Locate Wheel

Finds or downloads the wheel file for the installed package version.

- First checks pip's cache for the wheel
- If not cached, downloads fresh using `pip download`
- Uses pip to ensure correct platform-specific wheel is selected

### Step 2: Compute Wheel Hash

Computes the SHA256 hash of the wheel file using chunked reading for memory efficiency.

```python
sha256_hash = hashlib.sha256()
with open(file_path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        sha256_hash.update(chunk)
return sha256_hash.hexdigest()
```

### Step 3: Fetch and Verify Attestation

Fetches package metadata from the Simple API (PEP 691) and the attestation from the integrity API.

**Verifications performed:**
- Wheel hash matches the index's published hash
- Attestation subject digest matches the wheel hash

### Step 4: Verify Attestation Signature

Uses cosign to verify the RSA-4096 signature on the attestation.

**Process:**
1. Extract base64-encoded statement and signature from DSSE envelope
2. Decode both to raw bytes
3. Create DSSE PAE (Pre-Authentication Encoding)
4. Run `cosign verify-blob` with the public key

**What is PAE?**

PAE (Pre-Authentication Encoding) binds the payload type and length to the signature:

```
DSSEv1 28 application/vnd.in-toto+json 883 {"_type":"https://in-toto.io/...
```

This prevents:
- **Type confusion attacks**: Can't reuse signatures from different contexts
- **Length extension attacks**: Can't append data to signed messages
- **Ambiguity attacks**: Only one interpretation of signed data

### Step 5: Verify Installed Files

Verifies that installed files match the hashes in the wheel's RECORD.

**Why use the wheel's RECORD, not the installed RECORD?**

An attacker who modifies installed files could also modify the installed RECORD. By using the RECORD from the verified wheel (whose hash matches the signed attestation), we get authentic hashes from the build system.

## Output Example

```
============================================================
Verifying package: pyyaml
============================================================

Installed: PyYAML 6.0.3
Location: /home/user/.pyenv/versions/3.12.12/lib/python3.12/site-packages
[1/5] Locating wheel for PyYAML==6.0.3
  Not found in cache, downloading...
  Downloading PyYAML==6.0.3...
  Downloaded to: /tmp/pip_verify_.../pyyaml-6.0.3-0-cp312-....whl

[2/5] Computing wheel SHA256
  Wheel: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
  SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

[3/5] Fetching Red Hat Trusted Libraries metadata and attestations
  Index SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...
  ✓ Wheel hash matches published hash

  Provenance URL found: https://packages.redhat.com/.../provenance/
  Attestation subject SHA256: df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...
  ✓ Attestation matches wheel hash

[4/5] Verifying attestation signature with cosign
  Public key: /path/to/redhat-release3.pub
  ✓ Signature verified successfully

[5/5] Verifying installed files against wheel's RECORD
  (Using RECORD from verified wheel, not from disk)
  Files verified: 31/31
  ✓ All installed files match wheel's RECORD

============================================================
✓ VERIFICATION PASSED for PyYAML 6.0.3
============================================================
```

### Verbose Output

With `--verbose`, the script also displays:

1. **Raw attestation JSON** - The complete attestation structure
2. **Decoded statement JSON** - The base64-decoded in-toto statement
3. **Each verified file** - Full path with ✓ or ✗ status

## Verification Chain

This script implements a complete chain of trust:

```
┌─────────────────────────────────────────────────────────────────┐
│                     VERIFICATION CHAIN                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Red Hat Private Key                                            │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────┐                                                │
│  │ Attestation │ ◄── Contains: wheel filename + SHA256 hash    │
│  │  Signature  │                                                │
│  └──────┬──────┘                                                │
│         │ verify with cosign (Step 4)                           │
│         ▼                                                       │
│  ┌─────────────┐                                                │
│  │ Attestation │ ◄── Proves: wheel was built by Red Hat        │
│  │   Subject   │                                                │
│  └──────┬──────┘                                                │
│         │ compare hashes (Step 3)                               │
│         ▼                                                       │
│  ┌─────────────┐                                                │
│  │    Wheel    │ ◄── Contains: RECORD with file hashes         │
│  │    Hash     │                                                │
│  └──────┬──────┘                                                │
│         │ extract RECORD, compare hashes (Step 5)               │
│         ▼                                                       │
│  ┌─────────────┐                                                │
│  │  Installed  │ ◄── Your actual files on disk                 │
│  │    Files    │                                                │
│  └─────────────┘                                                │
│                                                                 │
│  Result: Proves installed files came from Red Hat's build       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Attestations

Cryptographically signed statements about how software was built. They follow the [in-toto specification](https://in-toto.io/) and contain SLSA provenance:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "pyyaml-6.0.3-0-cp312-....whl",
      "digest": { "sha256": "df088c59..." }
    }
  ],
  "predicate": {
    "buildType": "https://konflux-ci.dev/PythonWheelBuild@v1",
    "builder": { "id": "https://konflux-ci.dev/calunga" },
    "metadata": { "buildFinishedOn": "2026-02-19T21:51:09Z" }
  }
}
```

### DSSE (Dead Simple Signing Envelope)

Standard format for signing arbitrary data. The payload is base64-encoded and accompanied by a signature over a PAE.

### RECORD File

CSV file inside every wheel listing all files with their SHA256 hashes:

```csv
package/__init__.py,sha256=abc123...,1234
package/module.py,sha256=def456...,5678
package-1.0.dist-info/RECORD,,
```

Hash format: `sha256=<base64url-encoded-digest>`

## Comparison to Individual Scripts

This script combines the functionality of all four individual scripts:

| Step | Individual Script | Function |
|------|-------------------|----------|
| 3 | `fetch_attestation.py` | Fetch attestation from integrity API |
| 4 | `verify_signature.py` | Verify DSSE signature with cosign |
| 2-3 | `verify_wheel_hash.py` | Compare wheel hash with attestation |
| 5 | `verify_installed_files.py` | Verify installed files against RECORD |

Use the individual scripts for:
- Learning how each step works
- Debugging specific verification failures
- Educational purposes

Use this combined script for:
- Production verification workflows
- CI/CD pipelines
- Verifying multiple packages at once

## Related Scripts

- [fetch_attestation.py](fetch_attestation.md) - Fetch and display attestations
- [verify_signature.py](verify_signature.md) - Verify DSSE signatures
- [verify_wheel_hash.py](verify_wheel_hash.md) - Verify wheel hashes
- [verify_installed_files.py](verify_installed_files.md) - Verify installed files
