# SPDX-License-Identifier: BSD-2

import io
from dataclasses import dataclass, fields
from typing import (
    Literal,
    Sequence,
    ClassVar,
    Optional,
    get_args,
    cast,
    Union,
)
from .constants import (
    TPM2_ST,
    TPM2_CC,
    TPMA_SESSION,
    TPM2_RC,
    TPM2_SU,
    TPMI_YES_NO,
    TPM2_SE,
    TPM2_ALG,
    TPM2_RH,
    TPM2_ECC,
    TPMA_LOCALITY,
    TPM2_EO,
    TPM2_CAP,
    TPM2_CLOCK,
    TPM_AT,
    TSS2_RC,
    TPM_FRIENDLY_INT,
)
from .types import (
    TPM2_HANDLE,
    TPM2B_NONCE,
    TPM2B_AUTH,
    TPM2B_DIGEST,
    TPML_ALG,
    TPM2B_MAX_BUFFER,
    TPM2B_ENCRYPTED_SECRET,
    TPMT_SYM_DEF,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_PUBLIC,
    TPM2B_DATA,
    TPML_PCR_SELECTION,
    TPM2B_PRIVATE,
    TPM2B_CREATION_DATA,
    TPMT_TK_CREATION,
    TPM2B_NAME,
    TPM2B_SENSITIVE,
    TPM2B_ID_OBJECT,
    TPM2B_SENSITIVE_DATA,
    TPM2B_TEMPLATE,
    TPMT_SYM_DEF_OBJECT,
    TPM2B_PUBLIC_KEY_RSA,
    TPMT_RSA_DECRYPT,
    TPM2B_ECC_POINT,
    TPMS_ALGORITHM_DETAIL_ECC,
    TPMT_KDF_SCHEME,
    TPM2B_IV,
    TPMT_TK_HASHCHECK,
    TPML_DIGEST_VALUES,
    TPMT_SIG_SCHEME,
    TPM2B_ATTEST,
    TPMT_SIGNATURE,
    TPMT_TK_VERIFIED,
    TPML_CC,
    TPM2B_EVENT,
    TPML_DIGEST,
    TPM2B_TIMEOUT,
    TPMT_TK_AUTH,
    TPM2B_OPERAND,
    TPMT_HA,
    TPMS_CONTEXT,
    TPMS_CAPABILITY_DATA,
    TPMT_PUBLIC_PARMS,
    TPM2B_NV_PUBLIC,
    TPM2B_MAX_NV_BUFFER,
    TPML_AC_CAPABILITIES,
    TPMS_AC_OUTPUT,
    TPM_OBJECT,
)
from .TSS2_Exception import TSS2_Exception
from ._libtpm2_pytss import ffi, lib
from tpm2_pytss.internal.utils import _chkrc

TPM2_HEADER_SIZE = 10


# TODO, add type hint for encrypted parameters
# TODO, add class representing encrypted data


class TPM_FIXED_INT(int):
    _mfunc = None
    _umfunc = None

    def __init_subclass__(cls):
        mfunc = getattr(lib, f"Tss2_MU_{cls.__name__}_Marshal", None)
        umfunc = getattr(lib, f"Tss2_MU_{cls.__name__}_Unmarshal", None)
        ctype = f"{cls.__name__} *"
        cls._mfunc = mfunc
        cls._umfunc = umfunc
        cls._ctype = ctype

    def marshal(self) -> bytes:
        if self._mfunc is None:
            raise NotImplementedError("no marshal method found")
        offset = ffi.new("size_t *")
        buf = ffi.new("uint8_t[4096]")
        _chkrc(self._mfunc(int(self), buf, 4096, offset))
        return bytes(buf[0 : offset[0]])

    @classmethod
    def unmarshal(cls, buf: bytes) -> tuple["TPM_FIXED_INT", int]:
        if cls._umfunc is None:
            raise NotImplementedError("no unmarshal method found")
        cdata = ffi.new(cls._ctype)
        offset = ffi.new("size_t *")
        _chkrc(cls._umfunc(buf, len(buf), offset, cdata))
        return cls(cdata[0]), offset[0]


class UINT16(TPM_FIXED_INT):
    pass


class UINT32(TPM_FIXED_INT):
    pass


class INT32(TPM_FIXED_INT):
    pass


class UINT64(TPM_FIXED_INT):
    pass


TPM2_TYPES_ALIAS = Union[TPM_FIXED_INT, TPM_FRIENDLY_INT, TPM_OBJECT, TPM2_HANDLE]


@dataclass
class tpm2_command_session:
    handle: TPM2_HANDLE
    nonce: TPM2B_NONCE
    attributes: TPMA_SESSION
    authorization: TPM2B_AUTH


@dataclass
class tpm2_response_session:
    nonce: TPM2B_NONCE
    attributes: TPMA_SESSION
    acknowledgment: TPM2B_DIGEST


@dataclass
class tpm2_command:
    tag: Literal[TPM2_ST.SESSIONS, TPM2_ST.NO_SESSIONS]
    command_code: ClassVar[TPM2_CC]
    handles: Sequence[TPM2_HANDLE]
    parameters: Sequence[TPM2_TYPES_ALIAS]
    sessions: Sequence[tpm2_command_session]
    _commands_: ClassVar[dict[TPM2_CC, type["tpm2_command"]]] = dict()

    def __init_subclass__(cls):
        tpm2_command._commands_[cls.command_code] = cls

    @classmethod
    def lookup_command_class(cls, command_code: TPM2_CC) -> type["tpm2_command"]:
        if command_code not in tpm2_command._commands_:
            raise TSS2_Exception(TSS2_RC.BASE_RC_NOT_IMPLEMENTED)
        return tpm2_command._commands_[command_code]

    @classmethod
    def num_handles(cls) -> int:
        for field in fields(cls):
            args = get_args(field.type)
            if field.name == "handles":
                return len(args)
        raise Exception("FIXME, add better exception")

    @classmethod
    def parameter_types(cls) -> Sequence[type[TPM2_TYPES_ALIAS]]:
        for field in fields(cls):
            args = get_args(field.type)
            if field.name == "parameters":
                return args
        raise Exception("FIXME, add better exception")


@dataclass
class tpm2_response:
    tag: Literal[TPM2_ST.SESSIONS, TPM2_ST.NO_SESSIONS]
    command_code: ClassVar[TPM2_CC]
    response_code: TPM2_RC
    handle: Optional[TPM2_HANDLE]
    parameters: Sequence[TPM2_TYPES_ALIAS]
    sessions: Sequence[tpm2_response_session]
    _commands_: ClassVar[dict[TPM2_CC, type["tpm2_response"]]] = dict()

    def __init_subclass__(cls):
        tpm2_response._commands_[cls.command_code] = cls

    @classmethod
    def lookup_response_class(cls, command_code: TPM2_CC) -> type["tpm2_response"]:
        if command_code not in tpm2_response._commands_:
            raise TSS2_Exception(TSS2_RC.BASE_RC_NOT_IMPLEMENTED)
        return tpm2_response._commands_[command_code]

    @classmethod
    def has_handle(cls) -> bool:
        for field in fields(cls):
            if field.name == "handle" and field.type == TPM2_HANDLE:
                return True
        return False

    @classmethod
    def parameter_types(cls) -> Sequence[type[TPM2_TYPES_ALIAS]]:
        for field in fields(cls):
            args = get_args(field.type)
            if field.name == "parameters":
                return args
        raise Exception("FIXME, add better exception")


@dataclass
class tpm2_startup_command(tpm2_command):
    command_code = TPM2_CC.Startup
    handles: tuple[()]
    parameters: tuple[TPM2_SU]


@dataclass
class tpm2_startup_response(tpm2_response):
    command_code = TPM2_CC.Startup
    handle: None
    parameters: tuple[()]


# shutdown
@dataclass
class tpm2_shutdown_command(tpm2_command):
    command_code = TPM2_CC.Shutdown
    handles: tuple[()]
    parameters: tuple[TPM2_SU]


@dataclass
class tpm2_shutdown_response(tpm2_response):
    command_code = TPM2_CC.Shutdown
    handle: None
    parameters: tuple[()]


# selftest
@dataclass
class tpm2_selftest_command(tpm2_command):
    command_code = TPM2_CC.SelfTest
    handles: tuple[()]
    parameters: tuple[TPMI_YES_NO]


@dataclass
class tpm2_selftest_response(tpm2_response):
    command_code = TPM2_CC.SelfTest
    handle: None
    parameters: tuple[()]


# incrementalselftest
@dataclass
class tpm2_incremental_selftest_command(tpm2_command):
    command_code = TPM2_CC.IncrementalSelfTest
    handles: tuple[()]
    parameters: tuple[TPML_ALG]


@dataclass
class tpm2_incremental_selftest_response(tpm2_response):
    command_code = TPM2_CC.IncrementalSelfTest
    handle: None
    parameters: tuple[TPML_ALG]


# gettestresult
@dataclass
class tpm2_get_test_result_command(tpm2_command):
    command_code = TPM2_CC.GetTestResult
    handles: tuple[()]
    parameters: tuple[()]


@dataclass
class tpm2_get_test_result_response(tpm2_response):
    command_code = TPM2_CC.GetTestResult
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2_RC]


# startauthsession
@dataclass
class tpm2_start_auth_session_command(tpm2_command):
    command_code = TPM2_CC.StartAuthSession
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[
        TPM2B_NONCE, TPM2B_ENCRYPTED_SECRET, TPM2_SE, TPMT_SYM_DEF, TPM2_ALG
    ]


@dataclass
class tpm2_start_auth_session_response(tpm2_response):
    command_code = TPM2_CC.StartAuthSession
    handle: TPM2_HANDLE
    parameters: tuple[TPM2B_NONCE]


# policyrestart
@dataclass
class tpm2_policy_restart_command(tpm2_command):
    command_code = TPM2_CC.PolicyRestart
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_restart_response(tpm2_response):
    command_code = TPM2_CC.PolicyRestart
    handle: None
    parameters: tuple[()]


# create
@dataclass
class tpm2_create_command(tpm2_command):
    command_code = TPM2_CC.Create
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[
        TPM2B_SENSITIVE_CREATE, TPM2B_PUBLIC, TPM2B_DATA, TPML_PCR_SELECTION
    ]


@dataclass
class tpm2_create_response(tpm2_response):
    command_code = TPM2_CC.Create
    handle: None
    parameters: tuple[
        TPM2B_PRIVATE, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION
    ]


# load
@dataclass
class tpm2_load_command(tpm2_command):
    command_code = TPM2_CC.Load
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_PRIVATE, TPM2B_PUBLIC]


@dataclass
class tpm2_load_response(tpm2_response):
    command_code = TPM2_CC.Load
    handle: TPM2_HANDLE
    parameters: tuple[TPM2B_NAME]


# loadexternal
@dataclass
class tpm2_load_external_command(tpm2_command):
    command_code = TPM2_CC.LoadExternal
    handles: tuple[()]
    parameters: tuple[TPM2B_SENSITIVE, TPM2B_PUBLIC, TPM2_RH]


@dataclass
class tpm2_load_external_response(tpm2_response):
    command_code = TPM2_CC.LoadExternal
    handle: TPM2_HANDLE
    parameters: tuple[TPM2B_NAME]


# readpublic
@dataclass
class tpm2_read_public_command(tpm2_command):
    command_code = TPM2_CC.ReadPublic
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_read_public_response(tpm2_response):
    command_code = TPM2_CC.ReadPublic
    handle: None
    parameters: tuple[TPM2B_PUBLIC, TPM2B_NAME, TPM2B_NAME]


# activatecredential
@dataclass
class tpm2_activate_credential_command(tpm2_command):
    command_code = TPM2_CC.ActivateCredential
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]


@dataclass
class tpm2_activate_credential_response(tpm2_response):
    command_code = TPM2_CC.ActivateCredential
    handle: None
    parameters: tuple[TPM2B_DIGEST]


# makecredential
@dataclass
class tpm2_make_credential_command(tpm2_command):
    command_code = TPM2_CC.MakeCredential
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPM2B_NAME]


@dataclass
class tpm2_make_credential_response(tpm2_response):
    command_code = TPM2_CC.MakeCredential
    handle: None
    parameters: tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]


# unseal
@dataclass
class tpm2_unseal_command(tpm2_command):
    command_code = TPM2_CC.Unseal
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_unseal_response(tpm2_response):
    command_code = TPM2_CC.Unseal
    handle: None
    parameters: tuple[TPM2B_SENSITIVE_DATA]


# objectchangeauth
@dataclass
class tpm2_object_change_auth_command(tpm2_command):
    command_code = TPM2_CC.ObjectChangeAuth
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_AUTH]


@dataclass
class tpm2_object_change_auth_response(tpm2_response):
    command_code = TPM2_CC.ObjectChangeAuth
    handle: None
    parameters: tuple[TPM2B_PRIVATE]


# createloaded
@dataclass
class tpm2_create_loaded_command(tpm2_command):
    command_code = TPM2_CC.CreateLoaded
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_SENSITIVE_CREATE, TPM2B_TEMPLATE]


@dataclass
class tpm2_create_loaded_response(tpm2_response):
    command_code = TPM2_CC.CreateLoaded
    handle: TPM2_HANDLE
    parameters: tuple[TPM2B_PRIVATE, TPM2B_PUBLIC, TPM2B_NAME]


# duplicate
@dataclass
class tpm2_duplicate_command(tpm2_command):
    command_code = TPM2_CC.Duplicate
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SYM_DEF_OBJECT]


@dataclass
class tpm2_duplicate_response(tpm2_response):
    command_code = TPM2_CC.Duplicate
    handle: None
    parameters: tuple[TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]


# rewrap
@dataclass
class tpm2_rewrap_command(tpm2_command):
    command_code = TPM2_CC.Rewrap
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_PRIVATE, TPM2B_NAME, TPM2B_ENCRYPTED_SECRET]


@dataclass
class tpm2_rewrap_response(tpm2_response):
    command_code = TPM2_CC.Rewrap
    handle: None
    parameters: tuple[TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]


# import
@dataclass
class tpm2_import_command(tpm2_command):
    command_code = TPM2_CC.Import
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[
        TPM2B_DATA,
        TPM2B_PUBLIC,
        TPM2B_PRIVATE,
        TPM2B_ENCRYPTED_SECRET,
        TPMT_SYM_DEF_OBJECT,
    ]


@dataclass
class tpm2_import_response(tpm2_response):
    command_code = TPM2_CC.Import
    handle: None
    parameters: tuple[TPM2B_PRIVATE]


# rsa_encrypt
@dataclass
class tpm2_rsa_encrypt_command(tpm2_command):
    command_code = TPM2_CC.RSA_Encrypt
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_PUBLIC_KEY_RSA, TPMT_RSA_DECRYPT, TPM2B_DATA]


@dataclass
class tpm2_rsa_encrypt_response(tpm2_response):
    command_code = TPM2_CC.RSA_Encrypt
    handle: None
    parameters: tuple[TPM2B_PUBLIC_KEY_RSA]


# rsa_decrypt
@dataclass
class tpm2_rsa_decrypt_command(tpm2_command):
    command_code = TPM2_CC.RSA_Decrypt
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_PUBLIC_KEY_RSA, TPMT_RSA_DECRYPT, TPM2B_DATA]


@dataclass
class tpm2_rsa_decrypt_response(tpm2_response):
    command_code = TPM2_CC.RSA_Decrypt
    handle: None
    parameters: tuple[TPM2B_PUBLIC_KEY_RSA]


# ecdh_keygen
@dataclass
class tpm2_ecdh_keygen_command(tpm2_command):
    command_code = TPM2_CC.ECDH_KeyGen
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_ecdh_keygen_response(tpm2_response):
    command_code = TPM2_CC.ECDH_KeyGen
    handle: None
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT]


# ecdh_zgen
@dataclass
class tpm2_ecdh_zgen_command(tpm2_command):
    command_code = TPM2_CC.ECDH_ZGen
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_ECC_POINT]


@dataclass
class tpm2_ecdh_zgen_response(tpm2_response):
    command_code = TPM2_CC.ECDH_ZGen
    handle: None
    parameters: tuple[TPM2B_ECC_POINT]


# ecc_parameters
@dataclass
class tpm2_ecc_parameters_command(tpm2_command):
    command_code = TPM2_CC.ECC_Parameters
    handles: tuple[()]
    parameters: tuple[TPM2_ECC]


@dataclass
class tpm2_ecc_parameters_response(tpm2_response):
    command_code = TPM2_CC.ECC_Parameters
    handle: None
    parameters: tuple[TPMS_ALGORITHM_DETAIL_ECC]


# zgen_2phase
@dataclass
class tpm2_zgen_2phase_command(tpm2_command):
    command_code = TPM2_CC.ZGen_2Phase
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT, TPM2_ALG, UINT16]


@dataclass
class tpm2_zgen_2phase_response(tpm2_response):
    command_code = TPM2_CC.ZGen_2Phase
    handle: None
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT]


# ecc_encrypt
@dataclass
class tpm2_ecc_encrypt_command(tpm2_command):
    command_code = TPM2_CC.ECC_Encrypt
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER, TPMT_KDF_SCHEME]


@dataclass
class tpm2_ecc_encrypt_response(tpm2_response):
    command_code = TPM2_CC.ECC_Encrypt
    handle: None
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_MAX_BUFFER, TPM2B_DIGEST]


# ecc_decrypt
@dataclass
class tpm2_ecc_decrypt_command(tpm2_command):
    command_code = TPM2_CC.ECC_Decrypt
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_MAX_BUFFER, TPM2B_DIGEST, TPMT_KDF_SCHEME]


@dataclass
class tpm2_ecc_decrypt_response(tpm2_response):
    command_code = TPM2_CC.ECC_Decrypt
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER]


# encryptdecrypt
@dataclass
class tpm2_encrypt_decrypt_command(tpm2_command):
    command_code = TPM2_CC.EncryptDecrypt
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPMI_YES_NO, TPM2_ALG, TPM2B_IV, TPM2B_MAX_BUFFER]


@dataclass
class tpm2_encrypt_decrypt_response(tpm2_response):
    command_code = TPM2_CC.EncryptDecrypt
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2B_IV]


# encryptdecrypt2
@dataclass
class tpm2_encrypt_decrypt2_command(tpm2_command):
    command_code = TPM2_CC.EncryptDecrypt2
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER, TPMI_YES_NO, TPM2_ALG, TPM2B_IV]


@dataclass
class tpm2_encrypt_decrypt2_response(tpm2_response):
    command_code = TPM2_CC.EncryptDecrypt2
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2B_IV]


# hash
@dataclass
class tpm2_hash_command(tpm2_command):
    command_code = TPM2_CC.Hash
    handles: tuple[()]
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2_ALG, TPM2_RH]


@dataclass
class tpm2_hash_response(tpm2_response):
    command_code = TPM2_CC.Hash
    handle: None
    parameters: tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK]


# mac
@dataclass
class tpm2_mac_command(tpm2_command):
    # this covers the hmac command as well
    command_code = TPM2_CC.MAC
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2_ALG]


@dataclass
class tpm2_mac_response(tpm2_response):
    command_code = TPM2_CC.MAC
    handle: None
    parameters: tuple[TPM2B_DIGEST]


# hmac
# Reuse the MAC command/response classes as the HMAC and MAC command are the same
tpm2_hmac_command = tpm2_mac_command
tpm2_hmac_response = tpm2_mac_response


# getrandom
@dataclass
class tpm2_get_random_command(tpm2_command):
    command_code = TPM2_CC.GetRandom
    handles: tuple[()]
    parameters: tuple[UINT16]


@dataclass
class tpm2_get_random_response(tpm2_response):
    command_code = TPM2_CC.GetRandom
    handle: None
    parameters: tuple[TPM2B_DIGEST]


# stirrandom
@dataclass
class tpm2_stir_random_command(tpm2_command):
    command_code = TPM2_CC.StirRandom
    handles: tuple[()]
    parameters: tuple[TPM2B_SENSITIVE_DATA]


@dataclass
class tpm2_stir_random_response(tpm2_response):
    command_code = TPM2_CC.StirRandom
    handle: None
    parameters: tuple[()]


# mac_start
@dataclass
class tpm2_mac_start_command(tpm2_command):
    # This covers HMAC_Start as well
    command_code = TPM2_CC.MAC_Start
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_AUTH, TPM2_ALG]


@dataclass
class tpm2_mac_start_response(tpm2_response):
    command_code = TPM2_CC.MAC_Start
    handle: TPM2_HANDLE
    parameters: tuple[()]


# Reuse MAC start command/reponse for HMAC start as they are the same command
tpm2_hmac_start_command = tpm2_mac_start_command
tpm2_hmac_start_response = tpm2_mac_start_response


# hashsequencestart
@dataclass
class tpm2_hash_sequence_start_command(tpm2_command):
    command_code = TPM2_CC.HashSequenceStart
    handles: tuple[()]
    parameters: tuple[TPM2B_AUTH, TPM2_ALG]


@dataclass
class tpm2_hash_sequence_start_response(tpm2_response):
    command_code = TPM2_CC.HashSequenceStart
    handle: TPM2_HANDLE
    parameters: tuple[()]


# sequenceupdate
@dataclass
class tpm2_sequence_update_command(tpm2_command):
    command_code = TPM2_CC.SequenceUpdate
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER]


@dataclass
class tpm2_sequence_update_response(tpm2_response):
    command_code = TPM2_CC.SequenceUpdate
    handle: None
    parameters: tuple[()]


# sequencecomplete
@dataclass
class tpm2_sequence_complete_command(tpm2_command):
    command_code = TPM2_CC.SequenceComplete
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2_RH]


@dataclass
class tpm2_sequence_complete_response(tpm2_response):
    command_code = TPM2_CC.SequenceComplete
    handle: None
    parameters: tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK]


# eventsequencecomplete
@dataclass
class tpm2_event_sequence_complete_command(tpm2_command):
    command_code = TPM2_CC.EventSequenceComplete
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER]


@dataclass
class tpm2_event_sequence_complete_response(tpm2_response):
    command_code = TPM2_CC.EventSequenceComplete
    handle: None
    parameters: tuple[TPML_DIGEST_VALUES]


# certify
@dataclass
class tpm2_certify_command(tpm2_command):
    command_code = TPM2_CC.Certify
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME]


@dataclass
class tpm2_certify_response(tpm2_response):
    command_code = TPM2_CC.Certify
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# certifycreation
@dataclass
class tpm2_certify_creation_command(tpm2_command):
    command_code = TPM2_CC.CertifyCreation
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPM2B_DIGEST, TPMT_SIG_SCHEME, TPMT_TK_CREATION]


@dataclass
class tpm2_certify_creation_response(tpm2_response):
    command_code = TPM2_CC.CertifyCreation
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# quote
@dataclass
class tpm2_quote_command(tpm2_command):
    command_code = TPM2_CC.Quote
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME, TPML_PCR_SELECTION]


@dataclass
class tpm2_quote_response(tpm2_response):
    command_code = TPM2_CC.Quote
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# getsessionauditdigest
@dataclass
class tpm2_get_session_audit_digest_command(tpm2_command):
    command_code = TPM2_CC.GetSessionAuditDigest
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME]


@dataclass
class tpm2_get_session_audit_digest_response(tpm2_response):
    command_code = TPM2_CC.GetSessionAuditDigest
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# getcommandauditdigest
@dataclass
class tpm2_get_command_audit_digest_command(tpm2_command):
    command_code = TPM2_CC.GetCommandAuditDigest
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME]


@dataclass
class tpm2_get_command_audit_digest_response(tpm2_response):
    command_code = TPM2_CC.GetCommandAuditDigest
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# gettime
@dataclass
class tpm2_get_time_command(tpm2_command):
    command_code = TPM2_CC.GetTime
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME]


@dataclass
class tpm2_get_time_response(tpm2_response):
    command_code = TPM2_CC.GetTime
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# certifyx509
@dataclass
class tpm2_certify_x509_command(tpm2_command):
    command_code = TPM2_CC.CertifyX509
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME, TPM2B_MAX_BUFFER]


@dataclass
class tpm2_certify_x509_response(tpm2_response):
    command_code = TPM2_CC.CertifyX509
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER, TPM2B_DIGEST, TPMT_SIGNATURE]


# commit
@dataclass
class tpm2_commit_command(tpm2_command):
    command_code = TPM2_CC.Commit
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_SENSITIVE_DATA, TPM2B_ECC_POINT]


@dataclass
class tpm2_commit_response(tpm2_response):
    command_code = TPM2_CC.Commit
    handle: None
    parameters: tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT, TPM2B_ECC_POINT, UINT16]


# ec_ephemeral
@dataclass
class tpm2_ec_ephemeral_command(tpm2_command):
    command_code = TPM2_CC.EC_Ephemeral
    handles: tuple[()]
    parameters: tuple[TPM2_ECC]


@dataclass
class tpm2_ec_ephemeral_response(tpm2_response):
    command_code = TPM2_CC.EC_Ephemeral
    handle: None
    parameters: tuple[TPM2B_ECC_POINT, UINT16]


# verifysignature
@dataclass
class tpm2_verify_signature_command(tpm2_command):
    command_code = TPM2_CC.VerifySignature
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPMT_SIGNATURE]


@dataclass
class tpm2_verify_signature_response(tpm2_response):
    command_code = TPM2_CC.VerifySignature
    handle: None
    parameters: tuple[TPMT_TK_VERIFIED]


# sign
@dataclass
class tpm2_sign_command(tpm2_command):
    command_code = TPM2_CC.Sign
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK]


@dataclass
class tpm2_sign_response(tpm2_response):
    command_code = TPM2_CC.Sign
    handle: None
    parameters: tuple[TPMT_SIGNATURE]


# setcommandcodeauditstatus
@dataclass
class tpm2_set_command_code_audit_status_command(tpm2_command):
    command_code = TPM2_CC.SetCommandCodeAuditStatus
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2_ALG, TPML_CC, TPML_CC]


@dataclass
class tpm2_set_command_code_audit_status_response(tpm2_response):
    command_code = TPM2_CC.SetCommandCodeAuditStatus
    handle: None
    parameters: tuple[()]


# pcr_extend
@dataclass
class tpm2_pcr_extend_command(tpm2_command):
    command_code = TPM2_CC.PCR_Extend
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPML_DIGEST_VALUES]


@dataclass
class tpm2_pcr_extend_response(tpm2_response):
    command_code = TPM2_CC.PCR_Extend
    handle: None
    parameters: tuple[()]


# pcr_event
@dataclass
class tpm2_pcr_event_command(tpm2_command):
    command_code = TPM2_CC.PCR_Event
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_EVENT]


@dataclass
class tpm2_pcr_event_response(tpm2_response):
    command_code = TPM2_CC.PCR_Event
    handle: None
    parameters: tuple[TPML_DIGEST_VALUES]


# pcr_read
@dataclass
class tpm2_pcr_read_command(tpm2_command):
    command_code = TPM2_CC.PCR_Read
    handles: tuple[()]
    parameters: tuple[TPML_PCR_SELECTION]


@dataclass
class tpm2_pcr_read_response(tpm2_response):
    command_code = TPM2_CC.PCR_Read
    handle: None
    parameters: tuple[UINT32, TPML_PCR_SELECTION, TPML_DIGEST]


# pcr_allocate
@dataclass
class tpm2_pcr_allocated_command(tpm2_command):
    command_code = TPM2_CC.PCR_Allocate
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPML_PCR_SELECTION]


@dataclass
class tpm2_pcr_allocate_response(tpm2_response):
    command_code = TPM2_CC.PCR_Allocate
    handle: None
    parameters: tuple[TPMI_YES_NO, UINT32, UINT32, UINT32]


# pcr_setauthpolicy
@dataclass
class tpm2_pcr_set_auth_policy_command(tpm2_command):
    command_code = TPM2_CC.PCR_SetAuthPolicy
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPM2_ALG, TPM2_RH]


@dataclass
class tpm2_pcr_set_auth_policy_response(tpm2_response):
    command_code = TPM2_CC.PCR_SetAuthPolicy
    handle: None
    parameters: tuple[()]


# pcr_setauthvalue
@dataclass
class tpm2_pcr_set_auth_value_command(tpm2_command):
    command_code = TPM2_CC.PCR_SetAuthValue
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_pcr_set_auth_value_response(tpm2_response):
    command_code = TPM2_CC.PCR_SetAuthValue
    handle: None
    parameters: tuple[()]


# pcr_reset
@dataclass
class tpm2_pcr_reset_command(tpm2_command):
    command_code = TPM2_CC.PCR_Reset
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_pcr_reset_response(tpm2_response):
    command_code = TPM2_CC.PCR_Reset
    handle: None
    parameters: tuple[()]


# policysigned
@dataclass
class tpm2_policy_signed_command(tpm2_command):
    command_code = TPM2_CC.PolicySigned
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_NONCE, TPM2B_DIGEST, TPM2B_NONCE, INT32, TPMT_SIGNATURE]


@dataclass
class tpm2_policy_signed_response(tpm2_response):
    command_code = TPM2_CC.PolicySigned
    handle: None
    parameters: tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH]


# policysecret
@dataclass
class tpm2_policy_secret_command(tpm2_command):
    command_code = TPM2_CC.PolicySecret
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_NONCE, TPM2B_DIGEST, TPM2B_NONCE, INT32]


@dataclass
class tpm2_policy_secret_response(tpm2_response):
    command_code = TPM2_CC.PolicySecret
    handle: None
    parameters: tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH]


# policyticket
@dataclass
class tpm2_policy_ticket_command(tpm2_command):
    command_code = TPM2_CC.PolicyTicket
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[
        TPM2B_TIMEOUT, TPM2B_DIGEST, TPM2B_NONCE, TPM2B_NAME, TPMT_TK_AUTH
    ]


@dataclass
class tpm2_policy_ticket_response(tpm2_response):
    command_code = TPM2_CC.PolicyTicket
    handle: None
    parameters: tuple[()]


# policyor
@dataclass
class tpm2_policy_or_command(tpm2_command):
    command_code = TPM2_CC.PolicyOR
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPML_DIGEST]


@dataclass
class tpm2_policy_or_response(tpm2_response):
    command_code = TPM2_CC.PolicyOR
    handle: None
    parameters: tuple[()]


# policypcr
@dataclass
class tpm2_policy_pcr_command(tpm2_command):
    command_code = TPM2_CC.PolicyPCR
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_policy_pcr_response(tpm2_response):
    command_code = TPM2_CC.PolicyPCR
    handle: None
    parameters: tuple[()]


# policylocality
@dataclass
class tpm2_policy_locality_command(tpm2_command):
    command_code = TPM2_CC.PolicyLocality
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPMA_LOCALITY]


@dataclass
class tpm2_policy_locality_response(tpm2_response):
    command_code = TPM2_CC.PolicyLocality
    handle: None
    parameters: tuple[()]


# policynv
@dataclass
class tpm2_policy_nv_command(tpm2_command):
    command_code = TPM2_CC.PolicyNV
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_OPERAND, UINT16, TPM2_EO]


@dataclass
class tpm2_policy_nv_response(tpm2_response):
    command_code = TPM2_CC.PolicyNV
    handle: None
    parameters: tuple[()]


# policycountertimer
@dataclass
class tpm2_policy_counter_timer_command(tpm2_command):
    command_code = TPM2_CC.PolicyCounterTimer
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_OPERAND, UINT16, TPM2_EO]


@dataclass
class tpm2_policy_counter_timer_response(tpm2_response):
    command_code = TPM2_CC.PolicyCounterTimer
    handle: None
    parameters: tuple[()]


# policycommandcode
@dataclass
class tpm2_command_code_command(tpm2_command):
    command_code = TPM2_CC.PolicyCommandCode
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2_CC]


@dataclass
class tpm2_command_code_response(tpm2_response):
    command_code = TPM2_CC.PolicyCommandCode
    handle: None
    parameters: tuple[()]


# policyphysicalpresence
@dataclass
class tpm2_policy_physical_presence_command(tpm2_command):
    command_code = TPM2_CC.PolicyPhysicalPresence
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_physical_presence_response(tpm2_response):
    command_code = TPM2_CC.PolicyPhysicalPresence
    handle: None
    parameters: tuple[()]


# policycphash
@dataclass
class tpm2_policy_cp_hash_command(tpm2_command):
    command_code = TPM2_CC.PolicyCpHash
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_policy_cp_hash_response(tpm2_response):
    command_code = TPM2_CC.PolicyCpHash
    handle: None
    parameters: tuple[()]


# policynamehash
@dataclass
class tpm2_policy_name_hash_command(tpm2_command):
    command_code = TPM2_CC.PolicyNameHash
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_policy_name_hash_response(tpm2_response):
    command_code = TPM2_CC.PolicyNameHash
    handle: None
    parameters: tuple[()]


# policyduplicationselect
@dataclass
class tpm2_policy_duplication_select_command(tpm2_command):
    command_code = TPM2_CC.PolicyDuplicationSelect
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_NAME, TPM2B_NAME, TPMI_YES_NO]


@dataclass
class tpm2_policy_duplication_select_response(tpm2_response):
    command_code = TPM2_CC.PolicyDuplicationSelect
    handle: None
    parameters: tuple[()]


# policyauthorize
@dataclass
class tpm2_policy_authorize_command(tpm2_command):
    command_code = TPM2_CC.PolicyAuthorize
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPM2B_NONCE, TPM2B_NAME, TPMT_TK_VERIFIED]


@dataclass
class tpm2_policy_authorize_response(tpm2_response):
    command_code = TPM2_CC.PolicyAuthorize
    handle: None
    parameters: tuple[()]


# policyauthvalue
@dataclass
class tpm2_policy_auth_value_command(tpm2_command):
    command_code = TPM2_CC.PolicyAuthValue
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_auth_value_response(tpm2_response):
    command_code = TPM2_CC.PolicyAuthValue
    handle: None
    parameters: tuple[()]


# policypassword
@dataclass
class tpm2_policy_password_command(tpm2_command):
    command_code = TPM2_CC.PolicyPassword
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_password_response(tpm2_response):
    command_code = TPM2_CC.PolicyPassword
    handle: None
    parameters: tuple[()]


# policygetdigest
@dataclass
class tpm2_policy_get_digest_command(tpm2_command):
    command_code = TPM2_CC.PolicyGetDigest
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_get_digest_response(tpm2_response):
    command_code = TPM2_CC.PolicyGetDigest
    handle: None
    parameters: tuple[TPM2B_DIGEST]


# policynvwritten
@dataclass
class tpm2_policy_nv_written_command(tpm2_command):
    command_code = TPM2_CC.PolicyNvWritten
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPMI_YES_NO]


@dataclass
class tpm2_policy_nv_written_response(tpm2_response):
    command_code = TPM2_CC.PolicyNvWritten
    handle: None
    parameters: tuple[()]


# policytemplate
@dataclass
class tpm2_policy_template_command(tpm2_command):
    command_code = TPM2_CC.PolicyTemplate
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_policy_template_response(tpm2_response):
    command_code = TPM2_CC.PolicyTemplate
    handle: None
    parameters: tuple[()]


# policyauthorizenv
@dataclass
class tpm2_policy_authorize_nv_command(tpm2_command):
    command_code = TPM2_CC.PolicyAuthorizeNV
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_policy_authorize_nv_response(tpm2_response):
    command_code = TPM2_CC.PolicyAuthorizeNV
    handle: None
    parameters: tuple[()]


# policycapability
@dataclass
class tpm2_policy_capability_command(tpm2_command):
    command_code = TPM2_CC.PolicyCapability
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_OPERAND, UINT16, TPM2_EO, TPM2_CAP, UINT32]


@dataclass
class tpm2_policy_capability_response(tpm2_response):
    command_code = TPM2_CC.PolicyCapability
    handle: None
    parameters: tuple[()]


# policyparameters
@dataclass
class tpm2_policy_parameters_command(tpm2_command):
    command_code = TPM2_CC.PolicyParameters
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST]


@dataclass
class tpm2_policy_parameters_response(tpm2_response):
    command_code = TPM2_CC.PolicyParameters
    handle: None
    parameters: tuple[()]


# createprimary
@dataclass
class tpm2_create_primary_command(tpm2_command):
    command_code = TPM2_CC.CreatePrimary
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[
        TPM2B_SENSITIVE_CREATE, TPM2B_PUBLIC, TPM2B_DATA, TPML_PCR_SELECTION
    ]


@dataclass
class tpm2_create_primary_response(tpm2_response):
    command_code = TPM2_CC.CreatePrimary
    handle: TPM2_HANDLE
    parameters: tuple[
        TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION, TPM2B_NAME
    ]


# hierarchycontrol
@dataclass
class tpm2_hierarchy_control_command(tpm2_command):
    command_code = TPM2_CC.HierarchyControl
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2_RH, TPMI_YES_NO]


@dataclass
class tpm2_hierarchy_control_response(tpm2_response):
    command_code = TPM2_CC.HierarchyControl
    handle: None
    parameters: tuple[()]


# setprimarypolicy
@dataclass
class tpm2_set_primary_policy_command(tpm2_command):
    command_code = TPM2_CC.SetPrimaryPolicy
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPM2_ALG]


@dataclass
class tpm2_set_primary_policy_response(tpm2_response):
    command_code = TPM2_CC.SetPrimaryPolicy
    handle: None
    parameters: tuple[()]


# changepps
@dataclass
class tpm2_change_pps_command(tpm2_command):
    command_code = TPM2_CC.ChangePPS
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_change_pps_response(tpm2_response):
    command_code = TPM2_CC.ChangePPS
    handle: None
    parameters: tuple[()]


# changeeps
@dataclass
class tpm2_change_eps_command(tpm2_command):
    command_code = TPM2_CC.ChangeEPS
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_change_eps_response(tpm2_response):
    command_code = TPM2_CC.ChangeEPS
    handle: None
    parameters: tuple[()]


# clear
@dataclass
class tpm2_clear_command(tpm2_command):
    command_code = TPM2_CC.Clear
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_clear_response(tpm2_response):
    command_code = TPM2_CC.Clear
    handle: None
    parameters: tuple[()]


# clearcontrol
@dataclass
class tpm2_clear_control_command(tpm2_command):
    command_code = TPM2_CC.ClearControl
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPMI_YES_NO]


@dataclass
class tpm2_clear_control_response(tpm2_response):
    command_code = TPM2_CC.ClearControl
    handle: None
    parameters: tuple[()]


# hierarchychangeauth
@dataclass
class tpm2_hierarchy_change_auth_command(tpm2_command):
    command_code = TPM2_CC.HierarchyChangeAuth
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_AUTH]


@dataclass
class tpm2_hierarchy_change_auth_response(tpm2_response):
    command_code = TPM2_CC.HierarchyChangeAuth
    handle: None
    parameters: tuple[()]


# dictionaryattacklockreset
@dataclass
class tpm2_dictionary_attack_clock_reset_command(tpm2_command):
    command_code = TPM2_CC.DictionaryAttackLockReset
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_dictionary_attack_clock_reset_response(tpm2_response):
    command_code = TPM2_CC.DictionaryAttackLockReset
    handle: None
    parameters: tuple[()]


# dictionaryattackparameters
@dataclass
class tpm2_dictionary_attack_parameters_command(tpm2_command):
    command_code = TPM2_CC.DictionaryAttackParameters
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[UINT32, UINT32, UINT32]


@dataclass
class tpm2_dictionary_attack_parameters_response(tpm2_response):
    command_code = TPM2_CC.DictionaryAttackParameters
    handle: None
    parameters: tuple[()]


# pp_commands
@dataclass
class tpm2_pp_commands_command(tpm2_command):
    command_code = TPM2_CC.PP_Commands
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPML_CC, TPML_CC]


@dataclass
class tpm2_pp_commands_response(tpm2_response):
    command_code = TPM2_CC.PP_Commands
    handle: None
    parameters: tuple[()]


# setalgorithmset
@dataclass
class tpm2_set_algorithm_set_command(tpm2_command):
    command_code = TPM2_CC.SetAlgorithmSet
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[UINT32]


@dataclass
class tpm2_set_algorithm_set_response(tpm2_response):
    command_code = TPM2_CC.SetAlgorithmSet
    handle: None
    parameters: tuple[()]


# fieldupgradestart
@dataclass
class tpm2_field_upgrade_start_command(tpm2_command):
    command_code = TPM2_CC.FieldUpgradeStart
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DIGEST, TPMT_SIGNATURE]


@dataclass
class tpm2_field_upgrade_start_response(tpm2_response):
    command_code = TPM2_CC.FieldUpgradeStart
    handle: None
    parameters: tuple[()]


# fieldupgradedata
@dataclass
class tpm2_field_upgrade_data_command(tpm2_command):
    command_code = TPM2_CC.FieldUpgradeData
    handles: tuple[()]
    parameters: tuple[TPM2B_MAX_BUFFER]


@dataclass
class tpm2_field_upgrade_data_response(tpm2_response):
    command_code = TPM2_CC.FieldUpgradeData
    handle: None
    parameters: tuple[TPMT_HA, TPMT_HA]


# firmwareread
@dataclass
class tpm2_firmware_read_command(tpm2_command):
    command_code = TPM2_CC.FirmwareRead
    handles: tuple[()]
    parameters: tuple[UINT32]


@dataclass
class tpm2_firmware_read_response(tpm2_response):
    command_code = TPM2_CC.FirmwareRead
    handle: None
    parameters: tuple[TPM2B_MAX_BUFFER]


# contextsave
@dataclass
class tpm2_context_save_command(tpm2_command):
    command_code = TPM2_CC.ContextSave
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_context_save_response(tpm2_response):
    command_code = TPM2_CC.ContextSave
    handle: None
    parameters: tuple[TPMS_CONTEXT]


# contextload
@dataclass
class tpm2_context_load_command(tpm2_command):
    command_code = TPM2_CC.ContextLoad
    handles: tuple[()]
    parameters: tuple[TPMS_CONTEXT]


@dataclass
class tpm2_context_load_response(tpm2_response):
    command_code = TPM2_CC.ContextLoad
    handle: TPM2_HANDLE
    parameters: tuple[()]


# flushcontext
@dataclass
class tpm2_flush_context_command(tpm2_command):
    command_code = TPM2_CC.FlushContext
    handles: tuple[()]
    parameters: tuple[TPM2_HANDLE]


@dataclass
class tpm2_flush_context_response(tpm2_response):
    command_code = TPM2_CC.FlushContext
    handle: None
    parameters: tuple[()]


# evictcontrol
@dataclass
class tpm2_evict_control_command(tpm2_command):
    command_code = TPM2_CC.EvictControl
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2_HANDLE]


@dataclass
class tpm2_evict_control_response(tpm2_response):
    command_code = TPM2_CC.EvictControl
    handle: None
    parameters: tuple[()]


# readclock
@dataclass
class tpm2_read_clock_command(tpm2_command):
    command_code = TPM2_CC.ReadClock
    handles: tuple[()]
    parameters: tuple[()]


@dataclass
class tpm2_read_clock_response(tpm2_response):
    command_code = TPM2_CC.ReadClock
    handle: None
    parameters: tuple[()]


# clockset
@dataclass
class tpm2_clock_set_command(tpm2_command):
    command_code = TPM2_CC.ClockSet
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[UINT64]


@dataclass
class tpm2_clock_set_response(tpm2_response):
    command_code = TPM2_CC.ClockSet
    handle: None
    parameters: tuple[()]


# clockrateadjust
@dataclass
class tpm2_clock_rate_adjust_command(tpm2_command):
    command_code = TPM2_CC.ClockRateAdjust
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2_CLOCK]


@dataclass
class tpm2_clock_rate_adjust_response(tpm2_response):
    command_code = TPM2_CC.ClockRateAdjust
    handle: None
    parameters: tuple[()]


# getcapability
@dataclass
class tpm2_get_capability_command(tpm2_command):
    command_code = TPM2_CC.GetCapability
    handles: tuple[()]
    parameters: tuple[TPM2_CAP, UINT32, UINT32]


@dataclass
class tpm2_get_capability_response(tpm2_response):
    command_code = TPM2_CC.GetCapability
    handle: None
    parameters: tuple[TPMI_YES_NO, TPMS_CAPABILITY_DATA]


# testparms
@dataclass
class tpm2_test_parms_command(tpm2_command):
    command_code = TPM2_CC.TestParms
    handles: tuple[()]
    parameters: tuple[TPMT_PUBLIC_PARMS]


@dataclass
class tpm2_test_parms_response(tpm2_response):
    command_code = TPM2_CC.TestParms
    handle: None
    parameters: tuple[()]


# setcapability, missing structures


# nv_definespace
@dataclass
class tpm2_nv_define_space_command(tpm2_command):
    command_code = TPM2_CC.NV_DefineSpace
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_AUTH, TPM2B_NV_PUBLIC]


@dataclass
class tpm2_nv_define_space_response(tpm2_response):
    command_code = TPM2_CC.NV_DefineSpace
    handle: None
    parameters: tuple[()]


# nv_undefinespace
@dataclass
class tpm2_nv_undefine_space_command(tpm2_command):
    command_code = TPM2_CC.NV_UndefineSpace
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_undefine_space_response(tpm2_response):
    command_code = TPM2_CC.NV_UndefineSpace
    handle: None
    parameters: tuple[()]


# nv_undefinespacespecial
@dataclass
class tpm2_nv_undefine_space_special_command(tpm2_command):
    command_code = TPM2_CC.NV_UndefineSpaceSpecial
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_undefine_space_special_response(tpm2_response):
    command_code = TPM2_CC.NV_UndefineSpaceSpecial
    handle: None
    parameters: tuple[()]


# nv_readpublic
@dataclass
class tpm2_nv_read_public_command(tpm2_command):
    command_code = TPM2_CC.NV_ReadPublic
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_read_public_response(tpm2_response):
    command_code = TPM2_CC.NV_ReadPublic
    handle: None
    parameters: tuple[TPM2B_NV_PUBLIC, TPM2B_NAME]


# nv_write
@dataclass
class tpm2_nv_write_command(tpm2_command):
    command_code = TPM2_CC.NV_Write
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER, UINT16]


@dataclass
class tpm2_nv_write_response(tpm2_response):
    command_code = TPM2_CC.NV_Write
    handle: None
    parameters: tuple[()]


# nv_increment
@dataclass
class tpm2_nv_increment_command(tpm2_command):
    command_code = TPM2_CC.NV_Increment
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_increment_response(tpm2_response):
    command_code = TPM2_CC.NV_Increment
    handle: None
    parameters: tuple[()]


# nv_extend
@dataclass
class tpm2_nv_extend_command(tpm2_command):
    command_code = TPM2_CC.NV_Extend
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER]


@dataclass
class tpm2_nv_extend_response(tpm2_response):
    command_code = TPM2_CC.NV_Extend
    handle: None
    parameters: tuple[()]


# nv_setbits
@dataclass
class tpm2_nv_set_bits_command(tpm2_command):
    command_code = TPM2_CC.NV_SetBits
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[UINT64]


@dataclass
class tpm2_nv_set_bits_response(tpm2_response):
    command_code = TPM2_CC.NV_SetBits
    handle: None
    parameters: tuple[()]


# nv_writelock
@dataclass
class tpm2_nv_write_lock_command(tpm2_command):
    command_code = TPM2_CC.NV_WriteLock
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_write_lock_response(tpm2_response):
    command_code = TPM2_CC.NV_WriteLock
    handle: None
    parameters: tuple[()]


# nv_globalwritelock
@dataclass
class tpm2_nv_global_write_lock_command(tpm2_command):
    command_code = TPM2_CC.NV_GlobalWriteLock
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_global_write_lock_response(tpm2_response):
    command_code = TPM2_CC.NV_GlobalWriteLock
    handle: None
    parameters: tuple[()]


# nv_read
@dataclass
class tpm2_nv_read_command(tpm2_command):
    command_code = TPM2_CC.NV_Read
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[UINT16, UINT16]


@dataclass
class tpm2_nv_read_response(tpm2_response):
    command_code = TPM2_CC.NV_Read
    handle: None
    parameters: tuple[TPM2B_MAX_NV_BUFFER]


# nv_readlock
@dataclass
class tpm2_nv_read_lock_command(tpm2_command):
    command_code = TPM2_CC.NV_ReadLock
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[()]


@dataclass
class tpm2_nv_read_lock_response(tpm2_response):
    command_code = TPM2_CC.NV_ReadLock
    handle: None
    parameters: tuple[()]


# nv_changeauth
@dataclass
class tpm2_nv_change_auth_command(tpm2_command):
    command_code = TPM2_CC.NV_ChangeAuth
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_AUTH]


@dataclass
class tpm2_nv_change_auth_response(tpm2_response):
    command_code = TPM2_CC.NV_ChangeAuth
    handle: None
    parameters: tuple[()]


# nv_certify
@dataclass
class tpm2_nv_certifiy_command(tpm2_command):
    command_code = TPM2_CC.NV_Certify
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_DATA, TPMT_SIG_SCHEME, UINT16, UINT16]


@dataclass
class tpm2_nv_certifiy_response(tpm2_response):
    command_code = TPM2_CC.NV_Certify
    handle: None
    parameters: tuple[TPM2B_ATTEST, TPMT_SIGNATURE]


# nv_definespace2, missing structure
# nv_readpublic2, missing structures


# ac_getcapability
@dataclass
class tpm2_ac_get_capability_command(tpm2_command):
    command_code = TPM2_CC.AC_GetCapability
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM_AT, UINT32]


@dataclass
class tpm2_ac_get_capability_response(tpm2_response):
    command_code = TPM2_CC.AC_GetCapability
    handle: None
    parameters: tuple[TPMI_YES_NO, TPML_AC_CAPABILITIES]


# ac_send
@dataclass
class tpm2_ac_send_command(tpm2_command):
    command_code = TPM2_CC.AC_Send
    handles: tuple[TPM2_HANDLE, TPM2_HANDLE, TPM2_HANDLE]
    parameters: tuple[TPM2B_MAX_BUFFER]


@dataclass
class tpm2_ac_send_response(tpm2_response):
    command_code = TPM2_CC.AC_Send
    handle: None
    parameters: tuple[TPMS_AC_OUTPUT]


# policy_ac_sendselect
@dataclass
class tpm2_policy_ac_send_select_command(tpm2_command):
    command_code = TPM2_CC.Policy_AC_SendSelect
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[TPM2B_NAME, TPM2B_NAME, TPM2B_NAME, TPMI_YES_NO]


@dataclass
class tpm2_policy_ac_send_select_response(tpm2_response):
    command_code = TPM2_CC.Policy_AC_SendSelect
    handle: None
    parameters: tuple[()]


# act_settimeout
@dataclass
class tpm2_act_set_timeout_command(tpm2_command):
    command_code = TPM2_CC.ACT_SetTimeout
    handles: tuple[TPM2_HANDLE]
    parameters: tuple[UINT32]


@dataclass
class tpm2_act_set_timeout_response(tpm2_response):
    command_code = TPM2_CC.ACT_SetTimeout
    handle: None
    parameters: tuple[()]


# vendor_tcg_test
@dataclass
class tpm2_vendor_tcg_test_command(tpm2_command):
    command_code = TPM2_CC.Vendor_TCG_Test
    handles: tuple[()]
    parameters: tuple[TPM2B_DATA]


@dataclass
class tpm2_vendor_tcg_test_response(tpm2_response):
    command_code = TPM2_CC.Vendor_TCG_Test
    handle: None
    parameters: tuple[TPM2B_DATA]


def read_and_unmarshal(
    data: bytes, *args: type[TPM2_TYPES_ALIAS]
) -> tuple[Sequence[TPM2_TYPES_ALIAS], int]:
    off = 0
    values: list[TPM2_TYPES_ALIAS] = []
    for cls in args:
        value, suboff = cls.unmarshal(data[off:])
        off += suboff
        values.append(value)
    return tuple(values), off


def read_command_sessions(fp) -> Sequence[tpm2_command_session]:
    size_data = fp.read(4)
    size = int.from_bytes(size_data, byteorder="big")
    data = fp.read(size)
    sessions: list[tpm2_command_session] = list()
    while len(data):
        (handle, nonce, attributes, authorization), off = read_and_unmarshal(
            data, TPM2_HANDLE, TPM2B_NONCE, TPMA_SESSION, TPM2B_AUTH
        )
        handle = cast(TPM2_HANDLE, handle)
        nonce = cast(TPM2B_NONCE, nonce)
        attributes = cast(TPMA_SESSION, attributes)
        authorization = cast(TPM2B_AUTH, authorization)
        session = tpm2_command_session(
            handle=handle,
            nonce=nonce,
            attributes=attributes,
            authorization=authorization,
        )
        sessions.append(session)
        data = data[off:]

    return tuple(sessions)


def read_command_header(fp) -> tuple[TPM2_ST, TPM2_CC, int]:
    data = fp.read(TPM2_HEADER_SIZE)
    (tag, size, command_code), off = read_and_unmarshal(data, TPM2_ST, UINT32, TPM2_CC)
    tag = cast(TPM2_ST, tag)
    size = cast(UINT32, size)
    command_code = cast(TPM2_CC, command_code)
    left = size - off
    return tag, command_code, left


def read_command(fp) -> tpm2_command:
    tag, cc, left = read_command_header(fp)
    data = fp.read(left)
    subfp = io.BytesIO(data)
    command = tpm2_command.lookup_command_class(cc)
    num_handles = command.num_handles()
    handles = []
    for _ in range(0, num_handles):
        handle_data = subfp.read(4)
        handle, _ = TPM2_HANDLE.unmarshal(handle_data)
        handles.append(handle)
    sessions: Sequence[tpm2_command_session] = []
    if tag == TPM2_ST.SESSIONS:
        sessions = read_command_sessions(subfp)
    # FIXME check for encrypted parameters here
    parameters = command.parameter_types()
    parameter_data = subfp.read()
    parameter_values, _ = read_and_unmarshal(parameter_data, *parameters)
    c = command(
        tag=tag,
        handles=handles,
        parameters=tuple(parameter_values),
        sessions=tuple(sessions),
    )
    return c


def read_response_sessions(fp) -> Sequence[tpm2_response_session]:
    size_data = fp.read(4)
    size, _ = UINT32.unmarshal(size_data)
    data = fp.read(size)
    off = 0
    sessions: list[tpm2_response_session] = []
    while len(data):
        (nonce, attributes, acknowledgment), off = read_and_unmarshal(
            data, TPM2B_NONCE, TPMA_SESSION, TPM2B_DIGEST
        )
        nonce = cast(TPM2B_NONCE, nonce)
        attributes = cast(TPMA_SESSION, attributes)
        acknowledgment = cast(TPM2B_DIGEST, acknowledgment)
        session = tpm2_response_session(
            nonce=nonce, attributes=attributes, acknowledgment=acknowledgment
        )
        sessions.append(session)
        data = data[off:]
    return tuple(sessions)


def read_response_header(fp) -> tuple[TPM2_ST, TPM2_RC, int]:
    data = fp.read(TPM2_HEADER_SIZE)
    (tag, size, response_code), off = read_and_unmarshal(data, TPM2_ST, UINT32, TPM2_RC)
    tag = cast(TPM2_ST, tag)
    size = cast(UINT32, size)
    response_code = cast(TPM2_RC, response_code)
    left = size - off
    return tag, response_code, left


def read_response(fp, command_code: TPM2_CC) -> tpm2_response:
    tag, response_code, left = read_response_header(fp)
    data = fp.read(left)
    subfp = io.BytesIO(data)
    if response_code != TPM2_RC.SUCCESS:
        return tpm2_response(
            tag=tag,
            response_code=response_code,
            handle=None,
            parameters=tuple(),
            sessions=tuple(),
        )
    response = tpm2_response.lookup_response_class(command_code)
    handle: Optional[TPM2_HANDLE] = None
    if response.has_handle():
        handle_data = subfp.read(4)
        handle, _ = TPM2_HANDLE.unmarshal(handle_data)
    if tag == TPM2_ST.SESSIONS:
        parameter_size_data = subfp.read(4)
        parameter_size = int.from_bytes(parameter_size_data, byteorder="big")
    else:
        parameter_size = -1
    parameters: Sequence[type[TPM2_TYPES_ALIAS]] = response.parameter_types()
    parameter_data = subfp.read(parameter_size)
    parameter_values: list[TPM2_TYPES_ALIAS] = []
    for p in parameters:
        pv, off = p.unmarshal(parameter_data)
        parameter_data = parameter_data[off:]
        parameter_values.append(pv)
    # FIXME check for encrypted sessions here
    sessions: Sequence[tpm2_response_session] = []
    if tag == TPM2_ST.SESSIONS:
        sessions = read_response_sessions(subfp)
    r = tpm2_response(
        tag=tag,
        response_code=response_code,
        handle=handle,
        parameters=tuple(parameter_values),
        sessions=tuple(sessions),
    )
    return r
