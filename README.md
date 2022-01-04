# tpm2-pytss
[![Tests](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml/badge.svg)](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-pytss/branch/master/graph/badge.svg?token=Nqs8anZr2B)](https://codecov.io/gh/tpm2-software/tpm2-pytss)
[![Documentation Status](https://readthedocs.org/projects/tpm2-pytss/badge/?version=latest)](https://tpm2-pytss.readthedocs.io/en/latest/?badge=latest)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![PyPI version](https://img.shields.io/pypi/v/tpm2-pytss.svg)](https://pypi.org/project/tpm2-pytss)

TPM2 TSS Python bindings for Enhanced System API (ESYS), Feature API (FAPI), Marshaling (MU), TCTI
Loader (TCTILdr) and RC Decoding (rcdecode) libraries. It also contains utility methods for wrapping
keys to TPM 2.0 data structures for importation into the TPM, unwrapping keys and exporting them
from the TPM, TPM-less makecredential command and name calculations, TSS2 PEM Key format support,
importing Keys from PEM, DER and SSH formats, conversion from tpm2-tools based command line strings
and loading tpm2-tools context files.

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
python3 -m pip install tpm2-ptss
```
**NOTE**: You may need option `--user` or sitewide permissions through something like `sudo`.

This is known to work with versions 2.4.0 of tpm2-tss or higher.

## Help

- Ask a question via an [issue](https://github.com/tpm2-software/tpm2-pytss/issues/new)
- Send an email to tpm2@lists.01.org
  - You can subscribe to the users mailing list here
    https://lists.01.org/postorius/lists/tpm2.lists.01.org/

## License

tpm2-pytss is distributed under the [BSD 2 Clause License](LICENSE).
