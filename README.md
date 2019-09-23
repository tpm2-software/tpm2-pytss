# tpm2-pytss

[![Build Status](https://travis-ci.org/tpm2-software/tpm2-pytss.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-pytss)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

TPM2 TSS Python bindings for Enhanced System API (ESYS).

Supported versions of Python are

- 3.5
- 3.6
- 3.7

## Install

This has been tested against TPM2 TSS 2.3.1

```console
$ python3 -m pip install tpm2-pytss
```

Or install from the master branch via GitHub

```console
$ python3 -m pip install git+https://github.com/tpm2-software/tpm2-pytss
```

See [`tests/`](tests/) folder for example usage.

## Contributing

- See [HACKING](HACKING.md)

## TODO

- Document need for ctypes for certain values, [example](https://github.com/tpm2-software/tpm2-pytss/blob/d84ab944c2795a27a076caf759ecfb31ab667446/tests/test_esys_auto_session_flags.py#L112-L133)
- `ESYS_TR_PTR` should be `SessionContext`
