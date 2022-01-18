# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc2] - 2022-01-18
### Fixed:
  - Partial fixes to handling of TPMA_NV strings.

### Added:
  - Documentation for tr_from_public in ESYS_TR class.

## [1.0.0-rc1] - 2022-01-10
### Fixed:
 - Misspellings in Code on things like RuntimeError.
 - Fix documentation of ESAPI methods and exceptions.
 - Double ESAPI.Close call resulting in "Esys_Finalize() Finalizing NULL context."
 - type hint for verify_signature was an int, should be a str.
 - Parent cdata memory being freed when no parent reference. This causes sub-field references to parent cdata to
   be invalid.
 - in util method unwrap, fix variable `encdupsens` does not exist, it is `decsens` instead.

### Changed:
 - Renamed ESAPI.set_auth to ESAPI.tr_set_auth for consistenency.
 - Use None over 0 for default auth_handle.

### Added:
 - Check for bad type enum type in ESAPI.load_blob.
 - Support for deprecation of `TPM2_RH_PW` in tpm2-tss with proper TPM2_RS_PW attribute.

## [1.0.0-rc0] - 2021-12-13
### Added
- Bindings to the Enanced System (ESAPI) API.
- Bindings to the Feature (FAPI) API .
- Bindings to Dynamic TCTI Loading (TCTILdr) API .
- Bindings to Marshalling and Unmarshalling (MU) API.
- Bindings to rc-decode.
- tpm2-tools context file loading support.
- TSS2 PEM format support. This file format is used in OpenSSL Engine and Provider projects.
- Utility routines for: TPM Less Make Credential, sensitive wrapping and unwrapping (import and duplication helpers).
