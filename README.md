# tpm2-pytss
[![Tests](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml/badge.svg)](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-pytss/branch/master/graph/badge.svg?token=Nqs8anZr2B)](https://codecov.io/gh/tpm2-software/tpm2-pytss)
[![Documentation Status](https://readthedocs.org/projects/tpm2-pytss/badge/?version=latest)](https://tpm2-pytss.readthedocs.io/en/latest/?badge=latest)
[![CodeQL](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/codeql.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![PyPI version](https://img.shields.io/pypi/v/tpm2-pytss.svg)](https://pypi.org/project/tpm2-pytss)

TPM2 TSS Python bindings for Enhanced System API (ESYS), Feature API (FAPI), Marshaling (MU), TCTI
Loader (TCTILdr), TCTIs, policy, and RC Decoding (rcdecode) libraries. It allows for custom TCTIs
written in Python as well. It also contains utility methods for wrapping keys to TPM 2.0 data
structures for importation into the TPM, unwrapping keys and exporting them from the TPM, TPM-less
makecredential command and name calculations, TSS2 PEM Key format support, importing Keys from PEM,
DER and SSH formats, conversion from tpm2-tools based command line strings and loading tpm2-tools
context files.

## Documentation

Documentation for the latest release is hosted at
https://tpm2-pytss.readthedocs.io/en/latest/index.html

## Installing

To install the master branch:
```bash
python3 -m pip install git+https://github.com/tpm2-software/tpm2-pytss.git
```

To install latest stable from PyPi:
```bash
python3 -m pip install tpm2-pytss
```
**NOTE**: You may need option `--user` or sitewide permissions through something like `sudo`.

This is known to work with versions 2.4.0 of tpm2-tss or higher.

## Help

- Ask a question via an [issue](https://github.com/tpm2-software/tpm2-pytss/issues/new)
- Send an email to the tpm2 list:
    - https://lists.linuxfoundation.org/mailman/listinfo/tpm2
- File a Security Bug by following the instructions in [docs/SECURITY.md](docs/SECURITY.md)

## License

tpm2-pytss is distributed under the [BSD 2 Clause License](LICENSE).
