tpm2-pytss Documentation
=========================

This project provides a Python API to access the `tpm2-tss <https://github.com/tpm2-software/tpm2-tss>`_. If you're looking for how to connect to a TPM 2.0 device
in Python, you're in the right place.

The core libraries provide are:

- tss2-esys: The Enhanced System API which is a simpler command interface to the TPM with full control and includes crypto protected session support: `See the ESAPI spec <https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/>`_.
- tss2-fapi: The Feature API is a high-level API to make interactions with the TPM as simple as possible and support automatic encrypted sessions when possible: `See the FAPI spec <https://trustedcomputinggroup.org/resource/tss-fapi/>`_.
- tss2-mu: The Marshaling and Unmarshaling API which provides serialization and deserialization of TPM data structures: `See the MU spec <https://trustedcomputinggroup.org/resource/tcg-tss-2-0-marshalingunmarshaling-api-specification/>`_.
- tss2-rc: The Response Code API, which provides a way to convert ``TSS2_RC`` error codes into human readable strings: `See the RC spec <https://trustedcomputinggroup.org/resource/tcg-tss-2-0-response-code-api-specification/>`_.
- tss2-tctildr: The TPM Command Transmission Interface, which provides a way to get bytes to and from a TPM: `See the TCTI spec <https://trustedcomputinggroup.org/resource/tss-tcti-specification/>`_.

Under the hood, bindings are provided via `CFFI <https://cffi.readthedocs.io/en/latest/>`_. However, the Python API abstracts things quite a bit so you'll have to write less code.

Supported versions of Python are:

- 3.5
- 3.6
- 3.7
- 3.8
- 3.9

.. toctree::
    :hidden:
    :maxdepth: 2
    :caption: Contents:

    install
    API <api>
    Testing <testing>
    Project Info <project>
    GitHub <https://github.com/tpm2-software/tpm2-pytss>
