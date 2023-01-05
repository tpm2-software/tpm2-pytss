# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.1.0-rc0 - 2022-01-05
### Fixed
- using tpm2-pytss in unit tests within a mocked environment see #481.

### Added
- tpm2-tools like strings via parse for TPM2_SYM_DEF and TPM2_SYM_DEF_OBJECT structures.
- support for algorithms strings in ESAPI start_auth_session.
- utils: credential_to_tools and tools_to_credential to convert to and from tpm2-tools makecredential outputs.
- TCTI: Add bindings to TCTISpiHelper.

## 2.0.0 - 2022-12-05
### Fixed
- Resolution of include directory search paths when building CFFI bindings.
- Typo in pip package name in README.
- Missing package pycparser dependency in setup.cfg.
- Minimum version of tss2-esys as 2.4.0.
- Reproducible documentation builds using `SOURCE_DATE_EPOCH`. See #376.
- documentation issues, such as cross linking, indentation and style.
- test/test_utils.py::TestUtils::test_make_credential_ecc_camellia when CAMELLIA is not supported.
- Stop leaking tpm simulator references in test harness.
- Limitation on 10 set policy callbacks, now has no hard limit, see #473

### Added
- **Experimental** bindings to the policy library tss2-policy. Require version 3.3+ of tpm2-tss to enable.
- Support for Python 3.11.
- Testing on CI for built wheel.
- PyTCTI class for writing Python Native TCTIs.

### Changed
- TCTI get\_poll\_handles now returning PollData object instead of ffi.CData.
- TCTI magic is now byte string eg b"\x1" of up to 8 bytes.

## 1.2.0 - 2022-06-14
### Added
- utils function to parse tpm2-tools PCR values as function: unmarshal_tools_pcr_values.
- official python 3.10 support.
- sm2 and sm4 tools like parsing support for TPMT_PUBLIC and TPM2B_PUBLIC structures.
- tpm2-tools compatible YAML encoding and decoding of TPM structures
### Removed
- pkgconfig as runtime dependency
- Official Python 3.6 support.
- internal distutils usage.
- sm3 and sm4 support IF the backing cryptography package supports it.
### Fixed:
- trsess_set_attributes attributes parameter should be a TPMA_SESSION or int, not just int.
- setup.cfg install_requires requirement that cryptography be version 3.0 or greater.
- Note in documentation incorrectly called None.
- ability to build a wheel and run tests from directory root. Note code for package is now under src folder.

## 1.1.0 - 2022-03-29
### Fixed
- Spelling of "Enhanced" in CHANGELOG for 1.0.0 release.
- Ensure that TPM2_GENERATED.VALUE is encoded the same way as other constants.
- Add support to unmarshal simple TPM2B types (such as TPM2B_ATTEST and TPM2B_NAME) directly using the 
  unmarshal method
- utils: catch the ImportError as "e" enabling raising the exception later
- types: add check in TPMS_CONTEXT.to_tools for session handles

### Changed
- Drop pkgconfig from runtime dependencies, thus no longer need dev packages of built bindings at runtime.
  - NOTE: Version information is cached, a change in the TSS libraries requires a rebuild of the bindings.

### Added
- Support session contexts from tpm2-tools as well as function to marshal context to tpm2-tools format.
- Support two new encoding/decoding classes to go to/from hex or json representation of objects.
- Support for creating EK from templates and optionally NV index based templates.
- Binding to `Esys_TR_GetTpmHandle` as `ESAPI` method `tr_get_tpm_handle`.

## [1.0.0] - 2022-01-24
### Added
- Bindings to the Enhanced System (ESAPI) API.
- Bindings to the Feature (FAPI) API .
- Bindings to Dynamic TCTI Loading (TCTILdr) API .
- Bindings to Marshalling and Unmarshalling (MU) API.
- Bindings to rc-decode.
- tpm2-tools context file loading support.
- TSS2 PEM format support. This file format is used in OpenSSL Engine and Provider projects.
- Utility routines for: TPM Less Make Credential, sensitive wrapping and unwrapping (import and duplication helpers).
