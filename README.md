# tpm2-pytss

[![Build Status](https://travis-ci.org/tpm2-software/tpm2-pytss.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-pytss)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/tpm2-software/tpm2-pytss.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-pytss/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![PyPI version](https://img.shields.io/pypi/v/tpm2-pytss.svg)](https://pypi.org/project/tpm2-pytss)

TPM2 TSS Python bindings for Enhanced System API (ESYS).

Supported versions of Python are

- 3.5
- 3.6
- 3.7
- 3.8

## Features

We support the FAPI, ESAPI, and marshalling library.

## Dependencies

This has been tested against TPM2 TSS 2.4.0, SWIG 3 and SWIG 4.

### tpm2-tss

You need to install tpm2-tss prior to installing this,
[INSTALL.md](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

### pkg-config

You need to install pkg-config

### swig

You need to install [`swig`](http://swig.org/)

#### Ubuntu

```console
$ sudo apt-get -y install swig pkg-config
```

### ldconfig

When you ran `./configure` for tpm2-tss if you didn't supply a prefix it usually
defaults to `/usr/local/`. When you ran `make install` it then installed the
libraries under that path. Your pacakge manager usually installs libraries to
`/usr`. If you properly configure the `ldconfig` tool, it'll make the libraries
you just installed available from within `/usr/local` (which means they won't
clash with things your package manager installs). If you don't configure it then
you might get this error:

```log
ImportError: libtss2-esys.so.0: cannot open shared object file: No such file or directory
```

We make a config file that tells `ldconfig` to look in `/usr/local/lib` for
shared libraries, then we run `ldconfig`.

```console
$ sudo mkdir -p /etc/ld.so.conf.d/
$ echo 'include /etc/ld.so.conf.d/*.conf' | sudo tee -a /etc/ld.so.conf
$ echo '/usr/local/lib' | sudo tee -a /etc/ld.so.conf.d/libc.conf
$ sudo ldconfig
```

> More info on ldconfig error: https://stackoverflow.com/a/17653893/3969496

## Install

Install from PyPi.

```console
$ python3 -m pip install tpm2-pytss
```

Or install from the Git repo

```console
$ git clone --depth 1 --recurse-submodules -b ${TPM2_PYTSS_VERSION} \
  https://github.com/tpm2-software/tpm2-pytss
$ cd tpm2-pytss
$ python3 -m pip install -e .
```

## Examples

See [`tests/`](tests/) folder for example usage.

## Testing

You need to have `tpm_server` installed in your path to run the tests.

Download the latest version from https://sourceforge.net/projects/ibmswtpm2/files/
and put it somewher in your `$PATH`.

```console
$ python3 setup.py test
```

## Logging

To get traces of all calls into the TSS, use the `TPM2_PYTSS_LOG_LEVEL`
environment variable.

```console
$ export TPM2_PYTSS_LOG_LEVEL=debug
```

Example logs:

```
test_random_length (tests.test_esys_get_random.TestGetRandom) ... DEBUG:asyncio:Using selector: EpollSelector
DEBUG:tpm2_pytss.util.swig:Tss2_TctiLdr_Initialize_Ex(
    name: mssim,
    conf: port=63684,
    context: <Swig Object of type 'TSS2_TCTI_CONTEXT **' at 0x7f5e63d8ea50>,
)
DEBUG:tpm2_pytss.util.swig:new_ctx_ptr(

)
DEBUG:tpm2_pytss.util.swig:Esys_Initialize(
    esys_context: <Swig Object of type 'ESYS_CONTEXT **' at 0x7f5e63d8e9f0>,
    tcti: <Swig Object of type 'TSS2_TCTI_CONTEXT *' at 0x7f5e63d8e5d0>,
    abiVersion: <tpm2_pytss.binding.TSS2_ABI_VERSION; proxy of <Swig Object of type 'TSS2_ABI_VERSION *' at 0x7f5e6337ab10> >,
)
DEBUG:tpm2_pytss.util.swig:ctx_ptr_value(
    obj: <Swig Object of type 'ESYS_CONTEXT **' at 0x7f5e63d8e9f0>,
)
DEBUG:tpm2_pytss.util.swig:Esys_Startup(
    esysContext: <Swig Object of type 'ESYS_CONTEXT *' at 0x7f5e63d8e7e0>,
    startupType: 0,
)
DEBUG:tpm2_pytss.util.swig:Esys_SetTimeout(
    esys_context: <Swig Object of type 'ESYS_CONTEXT *' at 0x7f5e63d8e7e0>,
    timeout: -1,
)
DEBUG:tpm2_pytss.util.swig:Esys_GetRandom(
    esysContext: <Swig Object of type 'ESYS_CONTEXT *' at 0x7f5e63d8e7e0>,
    shandle1: 4095,
    shandle2: 4095,
    shandle3: 4095,
    bytesRequested: 11,
    randomBytes: <Swig Object of type 'TPM2B_NONCE **' at 0x7f5e63d8e8d0>,
)
DEBUG:tpm2_pytss.util.swig:Esys_Finalize(
    context: <Swig Object of type 'ESYS_CONTEXT **' at 0x7f5e63d8e9f0>,
)
DEBUG:tpm2_pytss.util.swig:delete_ctx_ptr(
    obj: <Swig Object of type 'ESYS_CONTEXT **' at 0x7f5e63d8e9f0>,
)
```

## Contributing

- See [HACKING](HACKING.md)

## TODO

- Document need for ctypes for certain values, [example](https://github.com/tpm2-software/tpm2-pytss/blob/d84ab944c2795a27a076caf759ecfb31ab667446/tests/test_esys_auto_session_flags.py#L112-L133)
- `ESYS_TR_PTR` should be `SessionContext`
