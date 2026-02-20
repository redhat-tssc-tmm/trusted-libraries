# `list_packages_py`

## Usage

  ### List all packages
  `python list_packages.py`

  ### List versions for a specific package
  `python list_packages.py -p requests`

  ### List all packages with their versions (slower - one request per package)
  `python list_packages.py -v`

  The script reads credentials automatically from your pip config. You can also pass --index-url, --username, and --password to override.

### See file `trusted-libraries-<date>.txt`


# `verify_package_provenance.py`

Verifies installed packages come from the Red Hat Index, have been signed and not tampered with. The package in question needs to be installed - otherwise it can't verify that the installed version matches the signed version of the wheel on the index.

## Usage

```
python verify_package_provenance.py -h
usage: verify_package_provenance.py [-h] [--public-key PUBLIC_KEY] [--no-signature] [-v] [-q] packages [packages ...]

Verify Python package provenance against Red Hat Trusted Libraries attestations

positional arguments:
  packages              Package name(s) to verify

options:
  -h, --help            show this help message and exit
  --public-key PUBLIC_KEY, -k PUBLIC_KEY
                        Path to public key for signature verification (default: redhat-release3.pub in script directory)
  --no-signature        Skip attestation signature verification
  -v, --verbose         Print each file path as it's verified against the RECORD
  -q, --quiet           Only show final result

Examples:
  verify_package_provenance.py requests                              # Verify with default key
  verify_package_provenance.py --public-key /path/to/key.pub requests  # Use custom key
  verify_package_provenance.py --no-signature requests               # Skip signature verification
  verify_package_provenance.py numpy pandas                          # Verify multiple packages

This tool verifies:
  1. Your installed wheel matches what Red Hat Trusted Libraries has published
  2. If attestations exist, they match the wheel
  3. If public key is provided, attestation signature is verified with cosign
  4. Installed files haven't been modified since installation

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
      For signature verification, cosign CLI must be installed.


```

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL. It also retrieves the credentials by using `pip config list` - if you are using another means to authenticate with the index (that isn't shown via the aforementioned command), please check and modify the `get_index_config()` method as needed.

### Example

``` 
[🎩︎mnagel pulp-index] (main) $ python verify_package_provenance.py --verbose pymysql

============================================================
Verifying package: pymysql
============================================================

✗ Package 'pymysql' is not installed

[🎩︎mnagel pulp-index] (main) $ pip install pymysql
Looking in indexes: https://20235381%7Ctrusted-libraries:****@packages.redhat.com/trusted-libraries/python
Collecting pymysql
  Downloading https://packages.redhat.com/api/pulp-content/trusted-libraries/main/pymysql-1.1.2-0-py3-none-any.whl.metadata (4.3 kB)
Downloading https://packages.redhat.com/api/pulp-content/trusted-libraries/main/pymysql-1.1.2-0-py3-none-any.whl (46 kB)
Installing collected packages: pymysql
Successfully installed pymysql-1.1.2

[🎩︎mnagel pulp-index] (main) $ python verify_package_provenance.py --verbose pymysql

============================================================
Verifying package: pymysql
============================================================

Installed: PyMySQL 1.1.2
Location: /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages
[1/5] Locating wheel for PyMySQL==1.1.2
  Not found in cache, downloading...
  Downloading PyMySQL==1.1.2...
  Downloaded to: /tmp/pip_verify_wkcfdp1e/pymysql-1.1.2-0-py3-none-any.whl

[2/5] Computing wheel SHA256
  Wheel: pymysql-1.1.2-0-py3-none-any.whl
  SHA256: 473cf5e4b20a244469d5308993aca001f6323409e6b2d04b484b8ab2e80f28be

[3/5] Fetching Red Hat Trusted Libraries metadata and attestations
  Index SHA256: 473cf5e4b20a244469d5308993aca001f6323409e6b2d04b484b8ab2e80f28be
  ✓ Wheel hash matches published hash

  Provenance URL found: https://packages.redhat.com/pypi/trusted-libraries/main/integrity/pymysql/1.1.2/pymysql-1.1.2-0-py3-none-any.whl/provenance/
  Attestation subject SHA256: 473cf5e4b20a244469d5308993aca001f6323409e6b2d04b484b8ab2e80f28be
  ✓ Attestation matches wheel hash

[4/5] Verifying attestation signature with cosign
  Public key: /home/mnagel/Documents/appServices/calunga/pulp-index/redhat-release3.pub
  ✓ Signature verified successfully

[5/5] Verifying installed files against wheel's RECORD
  (Using RECORD from verified wheel, not from disk)
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/__init__.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/_auth.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/charset.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/connections.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/converters.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/cursors.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/err.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/optionfile.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/protocol.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/times.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/CLIENT.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/COMMAND.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/CR.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/ER.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/FIELD_TYPE.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/FLAG.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/SERVER_STATUS.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql/constants/__init__.py
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/licenses/LICENSE
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/METADATA
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/WHEEL
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/fromager-build-backend-requirements.txt
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/fromager-build-sdist-requirements.txt
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/fromager-build-settings
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/fromager-build-system-requirements.txt
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/top_level.txt
    ✓ /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages/pymysql-1.1.2.dist-info/pymysql-1.1.2-0.spdx.json
  Files verified: 27/27
  ✓ All installed files match wheel's RECORD

============================================================
✓ VERIFICATION PASSED for PyMySQL 1.1.2
============================================================

```

NOTE: The script fetches the attestation based on the package name and Integrity API URL, _*NOT*_ from the `provenance_url` in the package metadata (which is erroneous at the moment, but will be fixed -> we're in **Tech Preview**)


# `verify_attestation_signature.py`

Verifies the attestation signature of a package/wheel on the index - helper script. Attestation signature verification is also part of `verify_package_provenance.py` which verifies that __installed__ packages have been signed and come from the Red Hat package index.

## Usage

``` 
python verify_attestation_signature.py -h
usage: verify_attestation_signature.py [-h] [--public-key PUBLIC_KEY] [--full] package

Verify attestation signatures for packages from Red Hat Trusted Libraries

positional arguments:
  package               Package name to verify

options:
  -h, --help            show this help message and exit
  --public-key PUBLIC_KEY, -k PUBLIC_KEY
                        Path to public key (default: redhat-release3.pub in script directory)
  --full, -f            Show full attestation and statement JSON

Examples:
  verify_attestation_signature.py amqp                                    # Verify with default key
  verify_attestation_signature.py --public-key ../redhat-release3.pub amqp  # Use custom key
  verify_attestation_signature.py --full amqp                             # Show full attestation JSON

This script:
  1. Queries the package index for available wheels with attestations
  2. Fetches the attestation from the integrity API
  3. Extracts the in-toto statement and signature
  4. Constructs the DSSE PAE (Pre-Authentication Encoding)
  5. Verifies the signature using cosign

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL.
      Requires cosign CLI to be installed.
```

### Example

```
[🎩︎mnagel pulp-index] (main) $ python verify_attestation_signature.py --full amqp
============================================================
Attestation Signature Verification
============================================================

Package:    amqp
Public Key: /home/mnagel/Documents/appServices/calunga/pulp-index/redhat-release3.pub

[1/8] Checking cosign availability...
       cosign: OK

[2/8] Querying package metadata...
       Package found: OK

[3/8] Finding wheel with attestation...
       Wheel: amqp-5.3.1-0-py3-none-any.whl
       Version: 5.3.1
       Attestation available: Yes

[4/8] Fetching attestation from integrity API...
       Attestation fetched: OK

[5/8] Extracting statement and signature...
       Statement extracted: OK
       Signature extracted: OK

[6/8] Attestation details:

       Subject: amqp-5.3.1-0-py3-none-any.whl
       SHA256:  034b93b6620dd4db0899c5299ed8fb11b60d2cd6fbfb3d271bedbf9f62dc2a9d
       Builder: https://konflux-ci.dev/calunga
       Built:   2026-02-19T16:59:23Z

       Signature (base64, first 60 chars): kV1JAby99vpZ2cPCsyNgURQ/qUtbCA/CtLrn0h/UHPVjnNrGbj8R/OVME5aC...
       Signature decoded length: 512 bytes

--- Full Attestation (raw from API) ---
{
  "version": 1,
  "attestation_bundles": [
    {
      "publisher": {
        "prn": "prn:auth.user:111",
        "kind": "Pulp User"
      },
      "attestations": [
        {
          "version": 1,
          "envelope": {
            "signature": "kV1JAby99vpZ2cPCsyNgURQ/qUtbCA/CtLrn0h/UHPVjnNrGbj8R/OVME5aCQM9TZKXMPsa/cXxHO26YEody7AnyfKNxr+2wORbrj5fpNPbQoG53jFkxmPtgxgcR8YvIHXZs+9fo0Qm/NAEk2L3CsAo+8KY1yQF8lEgg6wb0ZuVxDgxo9SqHmK03+WPmP3ivOjebKoZqpIXLFkojh2cDVVwniQJQmeJsodCJEadSZ45YuobbNssmkJV3E/Q+8s/RFhaVzBa2vyTfqE2QIIJhycb+MavJ70cq2e2f1qXoQ2XG2NljfE6lOE1fk7hILRXKX/0jFhAzShIvzI66tSGnRMvBIfFijEPFrxXmFfELVczTSpW0xiIWsUFvs97Lil7K3p/8gwJn64iVL17nNQ4M+/Et/f19miBSuTBE71a04rI5dygxFpeksR+mdO+NQaUJBaRolZg0GY1NBkz/qU5gtwEgNKg8btN0w+nGSQhWui9axXLCazVo/Xbhww5SY040EKhm6Hv7G4EU+RN5CPcJx7I9/iDETgE8LKMhCkeqOdb8HJWbJ8Y0mm/qf6hDkQ8cxsyjVBDpil/VPavyxboVw9YN7TjpkdqLrl7RZ8dYpxOs5ll+kyd73kypP9JMMHdYqe7McRxp5XM6/xb2Jpi8hwq03rye06hc/gE4CcjPboM=",
            "statement": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOlt7Im5hbWUiOiJhbXFwLTUuMy4xLTAtcHkzLW5vbmUtYW55LndobCIsImRpZ2VzdCI6eyJzaGEyNTYiOiIwMzRiOTNiNjYyMGRkNGRiMDg5OWM1Mjk5ZWQ4ZmIxMWI2MGQyY2Q2ZmJmYjNkMjcxYmVkYmY5ZjYyZGMyYTlkIn19XSwicHJlZGljYXRlIjp7Il90eXBlIjoiaHR0cHM6Ly9pbi10b3RvLmlvL1N0YXRlbWVudC92MC4xIiwicHJlZGljYXRlIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8va29uZmx1eC1jaS5kZXYvUHl0aG9uV2hlZWxCdWlsZEB2MSIsImJ1aWxkZXIiOnsiaWQiOiJodHRwczovL2tvbmZsdXgtY2kuZGV2L2NhbHVuZ2EifSwibWV0YWRhdGEiOnsiYnVpbGRGaW5pc2hlZE9uIjoiMjAyNi0wMi0xOVQxNjo1OToyM1oiLCJjb21wbGV0ZW5lc3MiOnsiZW52aXJvbm1lbnQiOnRydWUsIm1hdGVyaWFscyI6dHJ1ZSwicGFyYW1ldGVycyI6dHJ1ZX0sInJlcHJvZHVjaWJsZSI6dHJ1ZX19LCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YwLjIiLCJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiMDM0YjkzYjY2MjBkZDRkYjA4OTljNTI5OWVkOGZiMTFiNjBkMmNkNmZiZmIzZDI3MWJlZGJmOWY2MmRjMmE5ZCJ9LCJuYW1lIjoiYW1xcC01LjMuMS0wLXB5My1ub25lLWFueS53aGwifV19fQ=="
          },
          "verification_material": null
        }
      ]
    }
  ]
}

--- Decoded Statement ---
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "amqp-5.3.1-0-py3-none-any.whl",
      "digest": {
        "sha256": "034b93b6620dd4db0899c5299ed8fb11b60d2cd6fbfb3d271bedbf9f62dc2a9d"
      }
    }
  ],
  "predicate": {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicate": {
      "buildType": "https://konflux-ci.dev/PythonWheelBuild@v1",
      "builder": {
        "id": "https://konflux-ci.dev/calunga"
      },
      "metadata": {
        "buildFinishedOn": "2026-02-19T16:59:23Z",
        "completeness": {
          "environment": true,
          "materials": true,
          "parameters": true
        },
        "reproducible": true
      }
    },
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "subject": [
      {
        "digest": {
          "sha256": "034b93b6620dd4db0899c5299ed8fb11b60d2cd6fbfb3d271bedbf9f62dc2a9d"
        },
        "name": "amqp-5.3.1-0-py3-none-any.whl"
      }
    ]
  }
}

[7/8] Preparing public key...
       Key type: Public-Key: (4096 bit)

[8/8] Verifying signature with cosign...

       Verifying DSSE signature against PAE...
       PAE size: 794 bytes
       PAE format: DSSEv1 <type_len> <type> <payload_len> <payload>
       Payload type: application/vnd.in-toto+json (27 bytes)
       Payload length: 751 bytes


============================================================
Verification Results
============================================================

SIGNATURE VERIFIED SUCCESSFULLY

The attestation signature is valid and was created with the
private key corresponding to: /home/mnagel/Documents/appServices/calunga/pulp-index/redhat-release3.pub

This confirms the attestation was signed by the expected authority.
```
