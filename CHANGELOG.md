# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
