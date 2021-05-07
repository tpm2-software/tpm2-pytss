# tpm2-pytss
[![Tests](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml/badge.svg)](https://github.com/tpm2-software/tpm2-pytss/actions/workflows/tests.yaml)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-pytss/branch/master/graph/badge.svg?token=Nqs8anZr2B)](https://codecov.io/gh/tpm2-software/tpm2-pytss)
[![Documentation Status](https://readthedocs.org/projects/tpm2-pytss/badge/?version=latest)](https://tpm2-pytss.readthedocs.io/en/latest/?badge=latest)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![PyPI version](https://img.shields.io/pypi/v/tpm2-pytss.svg)](https://pypi.org/project/tpm2-pytss)

TPM2 TSS Python bindings for Enhanced System API (ESYS).

## Documentation

Documentation for the latest release is hosted at
https://tpm2-pytss.readthedocs.io/en/latest/index.html

## Contributing

See [HACKING](HACKING.md)

## Help

- Ask a question via an [issue](https://github.com/tpm2-software/tpm2-pytss/issues/new)
- Send an email to tpm2@lists.01.org
  - You can subscribe to the users mailing list here
    https://lists.01.org/postorius/lists/tpm2.lists.01.org/
- Ask a question on the [Gitter chat](https://gitter.im/tpm2-software/community)

## License

tpm2-pytss is distributed under the [BSD 2 Clause License](LICENSE).

## TODOs

- Document need for ctypes for certain values, [example](https://github.com/tpm2-software/tpm2-pytss/blob/d84ab944c2795a27a076caf759ecfb31ab667446/tests/test_esys_auto_session_flags.py#L112-L133)
- `ESYS_TR_PTR` should be `SessionContext` (Maybe?)
