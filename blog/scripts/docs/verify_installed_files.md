# verify_installed_files.py

Verifies that the files installed on your system match the original contents of a wheel file by comparing hashes.

## Usage

```bash
python verify_installed_files.py <package_name>
python verify_installed_files.py pyyaml
python verify_installed_files.py --verbose numpy
```

## Options

- `--verbose`, `-v`: Print each file as it's verified

## What It Does

This script demonstrates how to verify that installed package files haven't been modified since installation. It compares the actual files on disk against the hashes recorded in the original wheel's RECORD file.

### Step 1: Get Information About Installed Package

Uses Python's `importlib.metadata` to find the installed package:
- Package name and version
- Installation location (site-packages directory)

### Step 2: Download Original Wheel

Downloads the matching wheel from the index using `pip download`. Using pip ensures the correct platform-specific wheel is selected.

### Step 3: Extract and Parse RECORD

Opens the wheel (which is a ZIP file) and extracts the RECORD file from the dist-info directory. Parses the CSV to get expected hashes for each file.

### Step 4: Verify Installed Files

For each file listed in RECORD:
1. Finds the corresponding installed file on disk
2. Computes its SHA256 hash
3. Compares with the expected hash from RECORD

## Output Example

```
======================================================================
Verifying installed files for: pyyaml
======================================================================

Step 1: Getting information about installed package...
  Name:     PyYAML
  Version:  6.0.3
  Location: /home/user/.pyenv/versions/3.12.12/lib/python3.12/site-packages

Step 2: Downloading original wheel from index...
  Using pip to download pyyaml==6.0.3...
  Downloaded: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl

Step 3: Extracting RECORD from wheel...
  Found RECORD at: pyyaml-6.0.3.dist-info/RECORD
  Found 31 files with hashes

  Sample RECORD entries:
    _yaml/__init__.py
      sha256=d3801eff9a2cc5a8...
    pyyaml.libs/libyaml-0-40b3dddf.so.2.0.5
      sha256=d590b9dffe5f7a91...
    yaml/__init__.py
      sha256=b19dfcc333d6a75d...
    ... and 28 more

Step 4: Verifying installed files against RECORD...


======================================================================
  Files verified: 31/31

  VERIFICATION PASSED

  All installed files match the original wheel's RECORD.
  This confirms the files haven't been modified since installation.
======================================================================
```

### Verbose Output

With `--verbose`, the script shows each file as it's verified:

```
Step 4: Verifying installed files against RECORD...

  Checking each file:
    OK: /home/user/.../site-packages/_yaml/__init__.py
    OK: /home/user/.../site-packages/pyyaml.libs/libyaml-0-40b3dddf.so.2.0.5
    OK: /home/user/.../site-packages/yaml/__init__.py
    OK: /home/user/.../site-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so
    OK: /home/user/.../site-packages/yaml/composer.py
    ...
```

## Key Concepts Explained

### Why Verify Installed Files?

When pip installs a wheel, it extracts the files to your site-packages directory. After installation, those files could potentially be:
- Modified by malware or an attacker
- Corrupted by disk errors
- Accidentally edited

By comparing the installed files against the hashes recorded in the original wheel's RECORD file, we can detect any modifications.

### Why Use the Wheel's RECORD, Not the Installed RECORD?

When pip installs a wheel, it also extracts the RECORD file. An attacker who modifies installed files could also update the RECORD to match. By downloading the original wheel (which we've verified via attestation), we get the authentic RECORD that was signed by the package builder.

This is the key insight: **use the RECORD from the verified wheel, not from disk**.

### What is the RECORD File?

Every wheel contains a RECORD file in its dist-info directory. It's a CSV file listing every file in the wheel with its hash and size:

```csv
package/__init__.py,sha256=abc123...,1234
package/module.py,sha256=def456...,5678
package-1.0.dist-info/METADATA,sha256=ghi789...,2048
package-1.0.dist-info/RECORD,,
```

Note: The RECORD file itself has no hash (it can't hash itself).

### RECORD Hash Format

The hash format is: `sha256=<base64url-encoded-digest>`

**Base64url encoding** (RFC 4648):
- Uses `-` instead of `+`
- Uses `_` instead of `/`
- Padding `=` may be omitted

The script handles the conversion from base64url to hex for comparison:

```python
# Add padding if needed
padding_needed = 4 - (len(b64_hash) % 4)
if padding_needed != 4:
    b64_hash += "=" * padding_needed

# Decode base64url to bytes, then to hex
hash_bytes = base64.urlsafe_b64decode(b64_hash)
hex_hash = hash_bytes.hex()
```

### The Complete Verification Chain

This script is the final link in the verification chain:

```
Attestation Signature ─┐
                       ├─> Proves wheel came from Red Hat
Wheel Hash Match ──────┘

Installed Files Match ────> Proves installed files came from that wheel
```

Combined with signature and hash verification, this proves your installed code came from Red Hat's authenticated build process.

## Related Scripts

- [fetch_attestation.py](fetch_attestation.md) - Fetch and display the attestation
- [verify_signature.py](verify_signature.md) - Verify the attestation signature
- [verify_wheel_hash.py](verify_wheel_hash.md) - Verify the wheel hash matches the attestation
