# verify_signature.py

Verifies the cryptographic signature on a package attestation using the cosign CLI tool.

## Usage

```bash
python verify_signature.py <package_name>
python verify_signature.py pyyaml
python verify_signature.py --public-key /path/to/key.pub numpy
```

## Requirements

- `pip install requests`
- `cosign` CLI tool ([installation guide](https://docs.sigstore.dev/cosign/installation/))
- Red Hat's public key file (default: `../../redhat-release3.pub`)

## What It Does

This script demonstrates how to verify the cryptographic signature on a package attestation. It walks through each step of DSSE (Dead Simple Signing Envelope) signature verification.

### Step 1: Fetch Package Info

Queries the Simple API to get the wheel filename and version.

### Step 2: Fetch Attestation

Retrieves the attestation from the integrity API.

### Step 3: Extract DSSE Envelope Components

The attestation contains a DSSE envelope with:
- `statement`: Base64-encoded in-toto statement (the payload)
- `signature`: Base64-encoded cryptographic signature

```json
{
  "envelope": {
    "statement": "eyJfdHlwZSI6Imh0dHBz...",
    "signature": "X07BJL7CVejYQoBzyOdo..."
  }
}
```

### Step 4: Decode Base64 Components

Converts the base64-encoded strings to raw bytes:
- Statement: ~883 bytes (the in-toto JSON)
- Signature: 512 bytes (RSA-4096 signature)

### Step 5: Create DSSE PAE (Pre-Authentication Encoding)

This is the critical step! The signature is NOT over the raw statement. Instead, it's over a PAE that includes metadata:

```
DSSEv1 28 application/vnd.in-toto+json 883 {"_type":"https://in-toto.io/...
└────┘ └┘ └──────────────────────────┘ └─┘ └─────────────────────────────
  v1   len        payload type        len         payload bytes
```

### Step 6: Verify with Cosign

Runs `cosign verify-blob` to verify the RSA signature:

```bash
cosign verify-blob \
  --key clean_key.pub \
  --signature signature.bin \
  --insecure-ignore-tlog=true \
  pae.bin
```

## Output Example

```
======================================================================
Verifying attestation signature for: pyyaml
======================================================================

Step 1: Fetching package info from Simple API...
  Package: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
  Version: 6.0.3

Step 2: Fetching attestation from integrity API...
  Attestation retrieved successfully

Step 3: Extracting DSSE envelope components...
  Statement (base64): eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbn...
  Signature (base64): X07BJL7CVejYQoBzyOdoj5lCvwVQ+SeZTs0+Jhmns2p86cwCI3...

Step 4: Decoding base64 components...
  Statement size: 883 bytes
  Signature size: 512 bytes

  Decoded statement preview:
    Subject: pyyaml-6.0.3-0-cp312-cp312-manylinux....whl
    SHA256:  df088c59bcc2fc6a1ed21fb2db644f9890782f4fe...

Step 5: Creating DSSE PAE (Pre-Authentication Encoding)...
  PAE header: DSSEv1 28 application/vnd.in-toto+json 883 {"_type":"https://...
  PAE total size: 926 bytes

Step 6: Verifying signature with cosign...
  Public key: /path/to/redhat-release3.pub

======================================================================
  SIGNATURE VALID: Signature verified successfully
======================================================================
```

## Key Concepts Explained

### What is DSSE?

DSSE (Dead Simple Signing Envelope) is a standard format for signing arbitrary data. It wraps the payload with:
- A payload type identifier
- The base64-encoded payload
- One or more signatures

### What is PAE?

PAE (Pre-Authentication Encoding) is how the data is prepared before signing. Instead of signing the raw payload, DSSE signs a structured message that includes the payload type and length.

**Why PAE prevents attacks:**

1. **Type confusion attacks**: By binding the payload type to the signature, an attacker cannot take a valid signature from one context (e.g., a config file) and apply it to another (e.g., an attestation).

2. **Length extension attacks**: By including explicit lengths, attackers cannot append malicious data to a signed message.

3. **Ambiguity attacks**: The structured format ensures there's exactly one way to interpret the signed data.

See the [DSSE specification](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) for details.

### PAE Format

```
DSSEv1 {type_length} {payload_type} {payload_length} {payload}
```

Where spaces are literal ASCII space characters (0x20).

### RSA-4096 Signatures

Red Hat uses RSA-4096 keys to sign attestations. The 512-byte signature (4096 bits) provides strong cryptographic assurance that the attestation came from the holder of the private key.

## Related Scripts

- [fetch_attestation.py](fetch_attestation.md) - Fetch and display the attestation
- [verify_wheel_hash.py](verify_wheel_hash.md) - Verify the wheel hash matches the attestation
