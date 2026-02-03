# Usage

  ## List all packages
  `python list_packages.py`

  ## List versions for a specific package
  `python list_packages.py -p requests`

  ## List all packages with their versions (slower - one request per package)
  `python list_packages.py -v`

  The script reads credentials automatically from your pip config. You can also pass --index-url, --username, and --password to override.

## Status as of 2026-02-03 (Tech Preview)

```
[🎩︎mnagel pulp-index] (main) $ python list_packages.py 
aiobotocore
aiohappyeyeballs
aiohttp
aioitertools
aiosignal
amqp
annotated-types
anyio
apscheduler
asgiref
attrs
babel
billiard
blinker
boto3
botocore
cachetools
calver
celery
certifi
cffi
charset-normalizer
click
click-didyoumean
click-plugins
click-repl
colorama
cython
distlib
django
et-xmlfile
exceptiongroup
expandvars
filelock
final-attestation-test
flask
flit-core
flit-scm
fresh-attestation-test
frozenlist
fsspec
googleapis-common-protos
greenlet
grpcio
grpcio-status
h11
hatch-fancy-pypi-readme
hatch-vcs
hatchling
httpcore
idna
iniconfig
itsdangerous
jinja2
jmespath
kombu
markdown-it-py
markupsafe
maturin
mdurl
meson
meson-python
multidict
my-test-package
ninja
numpy
oauthlib
packaging
pandas
pathspec
pendulum
pip
pkgconfig
platformdirs
pluggy
poetry-core
prompt-toolkit
propcache
protobuf
psutil
pyasn1
pyasn1-modules
pycparser
pydantic
pydantic-core
pygments
pyjwt
pyparsing
pyproject-metadata
pytest
python-dateutil
python-dotenv
requests
requests-oauthlib
rich
rpds-py
rsa
s3fs
s3transfer
scikit-build-core
semantic-version
setuptools
setuptools-rust
setuptools-scm
six
sniffio
sqlalchemy
sqlparse
test-attestation-pkg
test-pulp-upload
tomli
tomlkit
tqdm
trove-classifiers
typing-extensions
typing-inspection
tzdata
tzlocal
urllib3
versioneer
vine
virtualenv
wcwidth
werkzeug
wheel
wrapt
yarl

Total: 127 packages
```