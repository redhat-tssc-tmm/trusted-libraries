# `list_packages_py`

## Usage

  ### List all packages
  `python list_packages.py`

  ### List versions for a specific package
  `python list_packages.py -p requests`

  ### List all packages with their versions (slower - one request per package)
  `python list_packages.py -v`

  The script reads credentials automatically from your pip config. You can also pass --index-url, --username, and --password to override.

## See file `trusted-libraries-<date>.txt`


# `verify_package_provenance.py`

## Usage

```
python verify_package_provenance.py -h
usage: verify_package_provenance.py [-h] [-q] packages [packages ...]

Verify Python package provenance against Red Hat Trusted Libraries attestations

positional arguments:
  packages     Package name(s) to verify

options:
  -h, --help   show this help message and exit
  -q, --quiet  Only show final result

Examples:
  verify_package_provenance.py requests              # Verify the 'requests' package
  verify_package_provenance.py test-attestation-pkg  # Verify a package with attestations
  verify_package_provenance.py numpy pandas          # Verify multiple packages

This tool verifies:
  1. Your installed wheel matches what Red Hat Trusted Libraries has published
  2. If attestations exist, they match the wheel
  3. Installed files haven't been modified since installation

```

Note: Requires pip to be configured with Red Hat Trusted Libraries index URL. It also retrieves the credentials by using `pip config list` - if you are using another means to authenticate with the index (that isn't shown via the aforementioned command), please check and modify the `get_index_config()` method as needed.

## Example

``` 
[🎩︎mnagel pulp-index] (main) $ python verify_package_provenance.py numpy

============================================================
Verifying package: numpy
============================================================

Installed: numpy 2.4.2
Location: /home/mnagel/.pyenv/versions/3.12.12/lib/python3.12/site-packages
[1/4] Locating wheel for numpy==2.4.2
  Not found in cache, downloading...
  Downloading numpy==2.4.2...
  Downloaded to: /tmp/pip_verify_k56lxzzx/numpy-2.4.2-0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl

[2/4] Computing wheel SHA256
  Wheel: numpy-2.4.2-0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
  SHA256: 6d0171a75d29c8f61f4cece337f7f0ca5e0cfd28371c1e41f385a0a5b4755d68

[3/4] Fetching Red Hat Trusted Libraries metadata and attestations
  Index SHA256: 6d0171a75d29c8f61f4cece337f7f0ca5e0cfd28371c1e41f385a0a5b4755d68
  ✓ Wheel hash matches published hash

  Provenance URL found: https://packages.redhat.com/pypi/trusted-libraries/main/integrity/numpy/2.4.2/numpy-2.4.2-0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl/provenance/
  Attestation subject SHA256: 6d0171a75d29c8f61f4cece337f7f0ca5e0cfd28371c1e41f385a0a5b4755d68
  ✓ Attestation matches wheel hash

[4/4] Verifying installed files against wheel's RECORD
  (Using RECORD from verified wheel, not from disk)
  Files verified: 914/914
  ✓ All installed files match wheel's RECORD

============================================================
✓ VERIFICATION PASSED for numpy 2.4.2
============================================================


```

NOTE: The script fetches the attestation based on the package name and Integrity API URL, _*NOT*_ from the `provenance_url` in the package metadata (which is erroneous at the moment, but will be fixed -> we're in **Tech Preview**)
