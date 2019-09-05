tpm2-pytss Documentation
=========================

This project provides access to the ``tpm2-tss`` Enhanced System API (ESAPI).

Direct bindings are provided via SWIG. However, we've abstracted things a bit so
you'll have to write less code.

To view the functions in the Enhanced System API go to
https://trustedcomputinggroup.org/specifications-public-review/
and search for ``ESAPI`` on that page. The first result will be the latest
revision of the specification. That's where you can find details on what each
functions does.

The first thing you'll want to do is read section ``3.1 Top-Level ESAPI Usage
Model`` to understand how the API works at a high level.

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    esys
    tcti
    binding
