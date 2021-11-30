tpm2-pytss Documentation
=========================

This project provides access to the ``tpm2-tss`` Enhanced System API (ESAPI).

Direct bindings are provided via `CFFI <https://cffi.readthedocs.io/en/latest/>`_.
However, we've abstracted things a bit so you'll have to write less code.

To view the functions in the Enhanced System API go to
https://trustedcomputinggroup.org/specifications-public-review/
and search for ``ESAPI`` on that page. The first result will be the latest
revision of the specification. That's where you can find details on what each
functions does.

The first thing you'll want to do is read section ``3.1 Top-Level ESAPI Usage
Model`` to understand how the API works at a high level.

Supported versions of Python are

- 3.5
- 3.6
- 3.7
- 3.8
- 3.9

Features
--------

tpm2-pytss provides bindings to the Enhanced System API (ESYS), Feature API (FAPI), Marshaling (MU), TCTI
Loader (TCTILdr) and RC Decoding (rcdecode) libraries. It also contains utility methods for wrapping
keys to TPM 2.0 data structures for importation into the TPM, unwrapping keys and exporting them
from the TPM, TPM-less makecredential command and name calculations, TSS2 PEM Key format support,
importing Keys from PEM, DER and SSH formats, conversion from tpm2-tools based command line strings
and loading tpm2-tools context files.


- :doc:`/esys`
- :doc:`/fapi`
- :doc:`/utils`
- :doc:`/tsskey`
- :doc:`/tcti`

Dependencies
------------

The python package will install the required python dependencies when you
perform something like a `pip install`. However, one must satisfy the the
dependencies on the following native libraries that comprise the tpm2-software suite:

Required Core Libraries provided by the tpm2-software/tpm2-tss project:

- tss2-esys
- tss2-fapi
- tss2-mu
- tss2-rcdecode
- tss2-tctildr
- tss2-rc

Optional TCTIs:
- tss2-tcti-device
- tss2-tcti-swtpm
- tss2-tcti-mssim
- tss2-tcti-libtpms
- tss2-tcti-pcap
- tss2-tcti-cmd

Optional TCTI's provided by tpm2-software/tpm2-abrmd:

- tss2-tcti-abrmd

These libraries are available through the package manager for most contemporary versions
of various Linux distros. However, you can consult the various tpm2-software projects for
help installing them from source:
- https://github.com/tpm2-software


Note that when you install from source, you may need to run ldconfig as illustrated below.

ldconfig
~~~~~~~~

When you ran ``./configure`` for tpm2-tss if you didn't supply a prefix it usually
defaults to ``/usr/local/``. When you ran ``make install`` it then installed the
libraries under that path. Your package manager usually installs libraries to
``/usr``. If you properly configure the ``ldconfig`` tool, it'll make the libraries
you just installed available from within ``/usr/local`` (which means they won't
clash with things your package manager installs). If you don't configure it then
you might get this error:

.. code-block::

    ImportError: libtss2-esys.so.0: cannot open shared object file: No such file or directory

We make a config file that tells ``ldconfig`` to look in ``/usr/local/lib`` for
shared libraries, then we run ``ldconfig``.

.. code-block:: console

    $ sudo mkdir -p /etc/ld.so.conf.d/
    $ echo 'include /etc/ld.so.conf.d/*.conf' | sudo tee -a /etc/ld.so.conf
    $ echo '/usr/local/lib' | sudo tee -a /etc/ld.so.conf.d/libc.conf
    $ sudo ldconfig

.. note::

    More info on ldconfig error: https://stackoverflow.com/a/17653893/3969496

Install
-------

Install from PyPi.

.. code-block:: console

    $ python3 -m pip install tpm2-pytss

Or install from the Git repo

.. code-block:: console

    $ git clone --depth 1 https://github.com/tpm2-software/tpm2-pytss
    $ cd tpm2-pytss
    $ python3 -m pip install -e .

Testing
-------

You need to have ``tpm_server`` or ``swtpm``  installed in your path to run the tests.

Download the latest version of tpm_server from https://sourceforge.net/projects/ibmswtpm2/files/
or swtpm from https://github.com/stefanberger/swtpm and put it somewhere in your ``$PATH``.

.. code-block:: console

    $ pip install -e .[dev]
    $ pytest -n$(nproc) -v test

Logging
-------

** In Progress ** Currently all the logging infrastructure is handled by the subbordiante libraries
and covered by tpm2-tss logging: https://github.com/tpm2-software/tpm2-tss/blob/master/doc/logging.md

This **MUST** not be considered stable API into the logging for the Python code and could be subject
to change.

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    types
    esys
    fapi
    utils
    tsskey
    tcti
    GitHub <https://github.com/tpm2-software/tpm2-pytss>
