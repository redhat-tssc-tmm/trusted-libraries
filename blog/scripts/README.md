# Package Provenance Verification Scripts

This directory contains educational Python scripts that demonstrate how to verify the provenance and integrity of Python packages from Red Hat Trusted Libraries.

Each script focuses on one aspect of the verification process, with detailed comments explaining the concepts for developers new to package attestations and cryptographic verification.

## Prerequisites

- Python 3.12 (will be expanded to other python versions, we start with 3.12)
    - best use a python virtual environment (venv)
    - if you're using a different python version but want to test drive this with 3.12, use version management, such as [pyenv](https://github.com/pyenv/pyenv)
- `pip install requests`
- `cosign` CLI tool (for signature verification: [installation guide](https://docs.sigstore.dev/cosign/system_config/installation/))
- pip configured with Red Hat Trusted Libraries index URL
- Red Hat's public key file (default: `../../redhat-release3.pub`)
  - The `release key 3` key file can be downloaded from [Red Hat's public key site](https://access.redhat.com/security/team/key)



## Scripts Overview

### Complete Verification

| Script | Purpose |
|--------|---------|
| [verify_package_provenance.py](docs/verify_package_provenance.md) | **Complete end-to-end verification** (combines all steps) |

### Individual Steps (Educational)

| Script | Purpose |
|--------|---------|
| [fetch_attestation.py](docs/fetch_attestation.md) | Fetch and display raw + decoded attestation |
| [verify_signature.py](docs/verify_signature.md) | Verify attestation signature with cosign (DSSE PAE) |
| [verify_wheel_hash.py](docs/verify_wheel_hash.md) | Verify wheel hash matches attestation subject |
| [verify_installed_files.py](docs/verify_installed_files.md) | Verify installed files against wheel's RECORD |

## Quick Start

```bash
# Complete verification 
python verify_package_provenance.py pyyaml

# Complete verification with verbose output
python verify_package_provenance.py --verbose pyyaml

# Verify multiple packages
python verify_package_provenance.py pyyaml urllib3 certifi
```

### Individual Steps (for learning/testing/debugging)

```bash
# Fetch and display an attestation
python fetch_attestation.py pyyaml

# Verify the attestation signature
python verify_signature.py pyyaml

# Verify the wheel hash matches the attestation
python verify_wheel_hash.py pyyaml

# Verify installed files match the wheel's RECORD
python verify_installed_files.py pyyaml
```

## Verification Chain

These scripts demonstrate a complete chain of trust:

| Step | Script | What It Proves |
|------|--------|----------------|
| 1 | `verify_signature.py` | The attestation was signed by Red Hat |
| 2 | `verify_wheel_hash.py` | The wheel matches what was attested |
| 3 | `verify_installed_files.py` | Installed files match the verified wheel |

**Combined result:** Proves your installed code came from Red Hat's build.

## Key Concepts

### Attestations
Cryptographically signed statements about how a software artifact was built. They follow the [in-toto](https://in-toto.io/) specification and contain SLSA provenance information.

### DSSE (Dead Simple Signing Envelope)
A standard format for signing arbitrary data. The payload (in-toto statement) is base64-encoded and accompanied by a signature.

### PAE (Pre-Authentication Encoding)
The format used to prepare data for signing in DSSE. It binds the payload type and length to prevent various attacks. Format: `DSSEv1 {type_len} {type} {payload_len} {payload}`

### RECORD File
A CSV file inside every wheel listing all files with their SHA256 hashes. Used to verify file integrity after installation.

## Related Resources

- [in-toto Specification](https://github.com/in-toto/docs)
- [SLSA Provenance](https://slsa.dev/provenance/)
- [DSSE Protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [PEP 503 - Simple Repository API](https://peps.python.org/pep-0503/)
- [PEP 691 - JSON Simple API](https://peps.python.org/pep-0691/)
- [Sigstore/Cosign](https://docs.sigstore.dev/cosign/overview/)
