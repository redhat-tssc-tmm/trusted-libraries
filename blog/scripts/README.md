# Package Provenance Verification Scripts

This directory contains educational Python scripts that demonstrate how to verify the provenance and integrity of Python packages from Red Hat Trusted Libraries.

Each script focuses on one aspect of the verification process, with detailed comments explaining the concepts for developers new to package attestations and cryptographic verification.

## Prerequisites

- Python 3.10+
- `pip install requests`
- `cosign` CLI tool (for signature verification)
- pip configured with Red Hat Trusted Libraries index URL

## Scripts Overview

| Script | Purpose |
|--------|---------|
| [fetch_attestation.py](docs/fetch_attestation.md) | Fetch and display raw + decoded attestation |
| [verify_signature.py](docs/verify_signature.md) | Verify attestation signature with cosign (DSSE PAE) |
| [verify_wheel_hash.py](docs/verify_wheel_hash.md) | Verify wheel hash matches attestation subject |
| [verify_installed_files.py](docs/verify_installed_files.md) | Verify installed files against wheel's RECORD |

## Quick Start

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

```
┌─────────────────────────────────────────────────────────────────────┐
│                        VERIFICATION CHAIN                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. ATTESTATION SIGNATURE (verify_signature.py)                     │
│     └─> Proves the attestation was signed by Red Hat               │
│                                                                     │
│  2. WHEEL HASH (verify_wheel_hash.py)                              │
│     └─> Proves the wheel matches what was attested                 │
│                                                                     │
│  3. INSTALLED FILES (verify_installed_files.py)                    │
│     └─> Proves installed files match the verified wheel            │
│                                                                     │
│  Combined: Proves your installed code came from Red Hat's build    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

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
