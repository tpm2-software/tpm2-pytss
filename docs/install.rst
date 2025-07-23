Installing
==========

Instructions for installing tpm2-pytss project.

Quick Start
-----------

- Install Dependencies: :ref:`Package Manager`
- Install Python Package: :ref:`pip install`

Install Dependencies
--------------------

The python package will install the required python dependencies when you perform something like a `pip install`. However, one must satisfy the
dependencies on the following native libraries that comprise the `tpm2-software <https://github.com/tpm2-software>`_ suite.

.. note::

   The **minimum supported version** of the **tpm2-tss** native library suite is **2.4.0**.

The Core Libraries provided by the `tpm2-tss <https://github.com/tpm2-software/tpm2-tss>`_ project:

Required Core Libraries:

- tss2-esys
- tss2-mu
- tss2-rcdecode
- tss2-tctildr

Optional Core Libraries:

- tss2-fapi

Optional TCTIs:

- tss2-tcti-device
- tss2-tcti-swtpm
- tss2-tcti-mssim
- tss2-tcti-libtpms
- tss2-tcti-pcap
- tss2-tcti-cmd

Optional TCTI's provided by `tpm2-abrmd <https://github.com/tpm2-software/tpm2-abrmd>`_ project:

- tss2-tcti-abrmd

.. note::

    One needs at least one TCTI to satisfy a connection to a TPM 2.0 device.

These libraries are available through the package manager for most contemporary versions
of various Linux distros. It is important to note that you will need the dev versions.
However, you can consult the various tpm2-software projects for help installing them from source
https://github.com/tpm2-software.

.. note::

    That when you install from source, you may need to run :ref:`run ldconfig`.

.. _Package Manager:

Installing Dependencies using a Package Manager
-----------------------------------------------

Example from Ubuntu 20.04 (No FAPI support):

.. code-block:: bash

    apt-get update
    apt-get install libtss2-dev

Example from Fedora 32:

.. code-block:: bash

    dnf update
    dnf install tpm2-tss-devel

.. _run ldconfig:

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

.. _pip install:

Install Using PyPi
------------------

Install from PyPi:

.. code-block:: console

    $ python3 -m pip install tpm2-pytss

.. note::

    You may need to use option ``--user`` or elevated permissions, i.e. ``sudo`` to install site-wide depending on your
    particular environment.

Or install from the Git repo:

.. code-block:: console

    $ git clone --depth 1 https://github.com/tpm2-software/tpm2-pytss
    $ cd tpm2-pytss
    $ python3 -m pip install -e .
