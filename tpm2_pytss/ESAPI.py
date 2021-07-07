"""
SPDX-License-Identifier: BSD-2
"""

from .types import *

from .utils import _chkrc, get_dptr, check_friendly_int
from .TCTI import TCTI

from typing import Union, Tuple, List


def get_cdata(value, expected, varname, allow_none=False, *args, **kwargs):
    tname = expected.__name__

    if value is None and allow_none:
        return ffi.NULL
    elif value is None:
        raise TypeError(f"expected {varname} to be {tname}, got None")

    if isinstance(value, ffi.CData):
        tipe = ffi.typeof(value)
        if tipe.kind == "pointer":
            tipe = tipe.item
        classname = fixup_classname(tipe)
        if classname != tname:
            raise TypeError(f"expected {varname} to be {tname}, got {tipe.cname}")
        return value

    vname = type(value).__name__
    parse_method = getattr(expected, "parse", None)
    if isinstance(value, (bytes, str)) and issubclass(expected, TPM2B_SIMPLE_OBJECT):
        bo = expected(value)
        return bo._cdata
    elif isinstance(value, str) and parse_method and callable(parse_method):
        return expected.parse(value, *args, **kwargs)._cdata
    elif issubclass(expected, TPML_OBJECT) and isinstance(value, list):
        return expected(value)._cdata
    elif not isinstance(value, expected):
        raise TypeError(f"expected {varname} to be {tname}, got {vname}")

    return value._cdata


def check_handle_type(handle, varname, expected=None, cls=ESYS_TR):
    if not isinstance(handle, int):
        raise TypeError(
            f"expected {varname} to be type int aka ESYS_TR, got {type(handle)}"
        )

    if expected is not None and handle not in expected:
        if len(expected) > 1:
            msg = f"expected {varname} to be one of {','.join([cls.to_string(x) for x in expected])}, got {cls.to_string(handle)}"
        else:
            msg = f"expected {varname} to be {cls.to_string(expected[0])}, got {cls.to_string(handle)}"

        raise ValueError(msg)


class ESAPI:
    def __init__(self, tcti: TCTI = None):
        self._tcti = tcti
        tctx = ffi.NULL if tcti is None else tcti._tcti_context

        self._ctx_pp = ffi.new("ESYS_CONTEXT **")
        _chkrc(lib.Esys_Initialize(self._ctx_pp, tctx, ffi.NULL))
        self._ctx = self._ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback) -> None:
        self.close()

    def close(self) -> None:
        lib.Esys_Finalize(self._ctx_pp)
        self._ctx = ffi.NULL

    def GetTcti(self) -> TCTI:
        if hasattr(self._tcti, "_tcti_context"):
            return self._tcti
        tctx = ffi.new("TSS2_TCTI_CONTEXT **")
        _chkrc(lib.Esys_GetTcti(self._ctx, tctx))
        return TCTI(tctx[0])

    @property
    def tcti(self) -> TCTI:
        return self.GetTcti()

    def tr_from_tpmpublic(
        self,
        handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        obj = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_TR_FromTPMPublic(
                self._ctx, handle, session1, session2, session3, obj,
            )
        )
        return obj[0]

    def set_auth(self, esys_tr: ESYS_TR, auth: Union[TPM2B_AUTH, bytes, str, None]):

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth")
        _chkrc(lib.Esys_TR_SetAuth(self._ctx, esys_tr, auth_cdata))

    def tr_get_name(self, handle: ESYS_TR) -> TPM2B_NAME:

        check_handle_type(handle, "handle")

        name = ffi.new("TPM2B_NAME **")
        _chkrc(lib.Esys_TR_GetName(self._ctx, handle, name))
        return TPM2B_NAME(_cdata=get_dptr(name, lib.Esys_Free))

    def startup(self, startup_type: TPM2_SU):

        check_friendly_int(startup_type, "startup_type", TPM2_SU)

        _chkrc(lib.Esys_Startup(self._ctx, startup_type))

    def shutdown(
        self,
        shutdown_type: TPM2_SU = TPM2_SU.STATE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_friendly_int(shutdown_type, "shutdown_type", TPM2_SU)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_Shutdown(self._ctx, session1, session2, session3, shutdown_type)
        )

    def self_test(
        self,
        full_test: bool,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        if not isinstance(full_test, bool):
            raise TypeError(
                f"Expected full_test to be type bool, got {type(full_test)}"
            )

        _chkrc(lib.Esys_SelfTest(self._ctx, session1, session2, session3, full_test))

    def incremental_self_test(
        self,
        to_test: TPML_ALG,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPML_ALG:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        toTest_cdata = get_cdata(to_test, TPML_ALG, "to_test")

        toDoList = ffi.new("TPML_ALG **")
        _chkrc(
            lib.Esys_IncrementalSelfTest(
                self._ctx, session1, session2, session3, toTest_cdata, toDoList
            )
        )
        return TPML_ALG(get_dptr(toDoList, lib.Esys_Free))

    def get_test_result(
        self,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        testResult = ffi.new("TPM2_RC *")
        _chkrc(
            lib.Esys_GetTestResult(
                self._ctx, session1, session2, session3, outData, testResult
            )
        )
        return (
            TPM2B_MAX_BUFFER(get_dptr(outData, lib.Esys_Free)),
            TPM2_RC(testResult[0]),
        )

    def start_auth_session(
        self,
        tpm_key: ESYS_TR,
        bind: ESYS_TR,
        nonce_caller: Union[TPM2B_NONCE, None],
        session_type: TPM2_SE,
        symmetric: TPMT_SYM_DEF,
        auth_hash: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(tpm_key, "tpm_key")
        check_handle_type(bind, "bind")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(session_type, "session_type", TPM2_SE)
        check_friendly_int(auth_hash, "auth_hash", TPM2_ALG)

        nonceCaller_cdata = get_cdata(
            nonce_caller, TPM2B_NONCE, "nonce_caller", allow_none=True
        )
        symmetric_cdata = get_cdata(symmetric, TPMT_SYM_DEF, "symmetric")

        sessionHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_StartAuthSession(
                self._ctx,
                tpm_key,
                bind,
                session1,
                session2,
                session3,
                nonceCaller_cdata,
                session_type,
                symmetric_cdata,
                auth_hash,
                sessionHandle,
            )
        )
        sessionHandleObject = sessionHandle[0]
        return sessionHandleObject

    def trsess_set_attributes(
        self, session: ESYS_TR, attributes: int, mask: int = 0xFF
    ):

        check_handle_type(session, "session")

        if not isinstance(attributes, int):
            raise TypeError(
                f"Expected attributes to be type int, got {type(attributes)}"
            )

        if not isinstance(mask, int):
            raise TypeError(f"Expected mask to be type int, got {type(attributes)}")

        _chkrc(lib.Esys_TRSess_SetAttributes(self._ctx, session, attributes, mask))

    def trsess_get_nonce_tpm(self, session: ESYS_TR) -> TPM2B_NONCE:

        check_handle_type(session, "session")

        nonce = ffi.new("TPM2B_NONCE **")

        _chkrc(lib.Esys_TRSess_GetNonceTPM(self._ctx, session, nonce))

        return TPM2B_NONCE(get_dptr(nonce, lib.Esys_Free))

    def policy_restart(
        self,
        session_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(session_handle, "session_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyRestart(
                self._ctx, session_handle, session1, session2, session3
            )
        )

    def create(
        self,
        parent_handle: ESYS_TR,
        in_sensitive: TPM2B_SENSITIVE_CREATE,
        in_public: Union[TPM2B_PUBLIC, str] = "rsa2048",
        outside_info: TPM2B_DATA = TPM2B_DATA(),
        creation_pcr: TPML_PCR_SELECTION = TPML_PCR_SELECTION(),
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")
        inSensitive_cdata = get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        outsideInfo_cdata = get_cdata(outside_info, TPM2B_DATA, "outside_info")
        creationPCR_cdata = get_cdata(creation_pcr, TPML_PCR_SELECTION, "creation_pcr")

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_Create(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                outsideInfo_cdata,
                creationPCR_cdata,
                outPrivate,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )
        return (
            TPM2B_PRIVATE(get_dptr(outPrivate, lib.Esys_Free)),
            TPM2B_PUBLIC(get_dptr(outPublic, lib.Esys_Free)),
            TPM2B_CREATION_DATA(get_dptr(creationData, lib.Esys_Free)),
            TPM2B_DIGEST(get_dptr(creationHash, lib.Esys_Free)),
            TPMT_TK_CREATION(get_dptr(creationTicket, lib.Esys_Free)),
        )

    def load(
        self,
        parent_handle: ESYS_TR,
        in_private: TPM2B_PRIVATE,
        in_public: TPM2B_PUBLIC,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")
        inPrivate_cdata = get_cdata(in_private, TPM2B_PRIVATE, "in_private")

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_Load(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inPrivate_cdata,
                inPublic_cdata,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def load_external(
        self,
        in_private: TPM2B_SENSITIVE,
        in_public: TPM2B_PUBLIC,
        hierarchy=ESYS_TR.NULL,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_friendly_int(hierarchy, "hierarchy", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPrivate_cdata = get_cdata(
            in_private, TPM2B_SENSITIVE, "in_private", allow_none=True
        )

        inPublic_cdata = get_cdata(in_public, TPM2B_PUBLIC, "in_public")

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_LoadExternal(
                self._ctx,
                session1,
                session2,
                session3,
                inPrivate_cdata,
                inPublic_cdata,
                hierarchy,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def read_public(
        self,
        object_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_PUBLIC, TPM2B_NAME, TPM2B_NAME]:

        check_handle_type(object_handle, "object_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outPublic = ffi.new("TPM2B_PUBLIC **")
        name = ffi.new("TPM2B_NAME **")
        qualifiedName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_ReadPublic(
                self._ctx,
                object_handle,
                session1,
                session2,
                session3,
                outPublic,
                name,
                qualifiedName,
            )
        )
        return (
            TPM2B_PUBLIC(get_dptr(outPublic, lib.Esys_Free)),
            TPM2B_NAME(get_dptr(name, lib.Esys_Free)),
            TPM2B_NAME(get_dptr(qualifiedName, lib.Esys_Free)),
        )

    def activate_credential(
        self,
        activate_handle: ESYS_TR,
        key_handle: ESYS_TR,
        credential_blob: TPM2B_ID_OBJECT,
        secret: TPM2B_ENCRYPTED_SECRET,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DIGEST:

        check_handle_type(activate_handle, "activate_handle")
        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        credentialBlob_cdata = get_cdata(
            credential_blob, TPM2B_ID_OBJECT, "credential_blob"
        )
        secret_cdata = get_cdata(secret, TPM2B_ENCRYPTED_SECRET, "secret")

        certInfo = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_ActivateCredential(
                self._ctx,
                activate_handle,
                key_handle,
                session1,
                session2,
                session3,
                credentialBlob_cdata,
                secret_cdata,
                certInfo,
            )
        )
        return TPM2B_DIGEST(get_dptr(certInfo, lib.Esys_Free))

    def make_credential(
        self,
        handle: ESYS_TR,
        credential: TPM2B_DIGEST,
        object_name: TPM2B_NAME,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]:

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        credential_cdata = get_cdata(credential, TPM2B_DIGEST, "credential")
        objectName_cdata = get_cdata(object_name, TPM2B_NAME, "object_name")

        credentialBlob = ffi.new("TPM2B_ID_OBJECT **")
        secret = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_MakeCredential(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                credential_cdata,
                objectName_cdata,
                credentialBlob,
                secret,
            )
        )
        return (
            TPM2B_ID_OBJECT(get_dptr(credentialBlob, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(get_dptr(secret, lib.Esys_Free)),
        )

    def unseal(
        self,
        item_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_SENSITIVE_DATA:

        check_handle_type(item_handle, "item_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        outData = ffi.new("TPM2B_SENSITIVE_DATA **")
        _chkrc(
            lib.Esys_Unseal(
                self._ctx, item_handle, session1, session2, session3, outData
            )
        )
        return TPM2B_SENSITIVE_DATA(get_dptr(outData, lib.Esys_Free))

    def object_change_auth(
        self,
        object_handle: ESYS_TR,
        parent_handle: ESYS_TR,
        new_auth: Union[TPM2B_AUTH, str, bytes],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PRIVATE:

        check_handle_type(object_handle, "object_handle")
        check_handle_type(parent_handle, "parent_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        newAuth_cdata = get_cdata(new_auth, TPM2B_AUTH, "new_auth")

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_ObjectChangeAuth(
                self._ctx,
                object_handle,
                parent_handle,
                session1,
                session2,
                session3,
                newAuth_cdata,
                outPrivate,
            )
        )
        return TPM2B_PRIVATE(get_dptr(outPrivate, lib.Esys_Free))

    def create_loaded(
        self,
        parent_handle: ESYS_TR,
        in_sensitive: TPM2B_SENSITIVE_CREATE,
        in_public: Union[TPM2B_PUBLIC, str] = "rsa2048",
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[ESYS_TR, TPM2B_PRIVATE, TPM2B_PUBLIC]:

        check_handle_type(parent_handle, "parent_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if isinstance(in_public, str):
            in_public = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(in_public).Marshal())

        inSensitive_cdata = get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        inPublic_cdata = get_cdata(in_public, TPM2B_TEMPLATE, "in_public")

        objectHandle = ffi.new("ESYS_TR *")
        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        _chkrc(
            lib.Esys_CreateLoaded(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                objectHandle,
                outPrivate,
                outPublic,
            )
        )
        objectHandleObject = objectHandle[0]
        return (
            objectHandleObject,
            TPM2B_PRIVATE(get_dptr(outPrivate, lib.Esys_Free)),
            TPM2B_PUBLIC(get_dptr(outPublic, lib.Esys_Free)),
        )

    def duplicate(
        self,
        object_handle: ESYS_TR,
        new_parent_handle: ESYS_TR,
        encryption_key_in: TPM2B_DATA,
        symmetric_alg: TPMT_SYM_DEF_OBJECT,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]:

        check_handle_type(object_handle, "object_handle")
        check_handle_type(new_parent_handle, "new_parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        encryptionKeyIn_cdata = get_cdata(
            encryption_key_in, TPM2B_DATA, "encryption_key_in", allow_none=True
        )
        symmetricAlg_cdata = get_cdata(
            symmetric_alg, TPMT_SYM_DEF_OBJECT, "symmetric_alg"
        )

        encryptionKeyOut = ffi.new("TPM2B_DATA **")
        duplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Duplicate(
                self._ctx,
                object_handle,
                new_parent_handle,
                session1,
                session2,
                session3,
                encryptionKeyIn_cdata,
                symmetricAlg_cdata,
                encryptionKeyOut,
                duplicate,
                outSymSeed,
            )
        )

        return (
            TPM2B_DATA(get_dptr(encryptionKeyOut, lib.Esys_Free)),
            TPM2B_PRIVATE(get_dptr(duplicate, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(get_dptr(outSymSeed, lib.Esys_Free)),
        )

    def rewrap(
        self,
        old_parent: ESYS_TR,
        new_parent: ESYS_TR,
        in_duplicate: TPM2B_PRIVATE,
        name: Union[TPM2B_NAME, bytes, str],
        in_sym_seed: TPM2B_ENCRYPTED_SECRET,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]:

        check_handle_type(old_parent, "old_parent")
        check_handle_type(new_parent, "new_parent")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inDuplicate_cdata = get_cdata(in_duplicate, TPM2B_PRIVATE, "in_duplicate")

        inSymSeed_cdata = get_cdata(in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed")

        name_cdata = get_cdata(name, TPM2B_NAME, "name")

        outDuplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Rewrap(
                self._ctx,
                old_parent,
                new_parent,
                session1,
                session2,
                session3,
                inDuplicate_cdata,
                name_cdata,
                inSymSeed_cdata,
                outDuplicate,
                outSymSeed,
            )
        )
        return (
            TPM2B_PRIVATE(get_dptr(outDuplicate, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(get_dptr(outSymSeed, lib.Esys_Free)),
        )

    def import_(
        self,
        parent_handle: ESYS_TR,
        encryption_key: Union[TPM2B_DATA, bytes, str],
        object_public: TPM2B_PUBLIC,
        duplicate: TPM2B_PRIVATE,
        in_sym_seed: TPM2B_ENCRYPTED_SECRET,
        symmetricAlg: TPMT_SYM_DEF_OBJECT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PRIVATE:

        check_handle_type(parent_handle, "parent_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        encryptionKey_cdata = get_cdata(encryption_key, TPM2B_DATA, "encryption_key")

        objectPublic_cdata = get_cdata(object_public, TPM2B_PUBLIC, "object_public")

        duplicate_cdata = get_cdata(duplicate, TPM2B_PRIVATE, "duplicate")

        inSymSeed_cdata = get_cdata(in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed")

        symmetricAlg_cdata = get_cdata(
            symmetricAlg, TPMT_SYM_DEF_OBJECT, "symmetricAlg"
        )

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_Import(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                encryptionKey_cdata,
                objectPublic_cdata,
                duplicate_cdata,
                inSymSeed_cdata,
                symmetricAlg_cdata,
                outPrivate,
            )
        )
        return TPM2B_PRIVATE(get_dptr(outPrivate, lib.Esys_Free))

    def rsa_encrypt(
        self,
        key_handle: ESYS_TR,
        message: Union[TPM2B_PUBLIC_KEY_RSA, bytes, str],
        in_scheme: TPMT_RSA_DECRYPT,
        label: Union[TPM2B_DATA, bytes, str, None] = None,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PUBLIC_KEY_RSA:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inScheme_cdata = get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        message_cdata = get_cdata(message, TPM2B_PUBLIC_KEY_RSA, "message")
        label_cdata = get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        outData = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Encrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                message_cdata,
                inScheme_cdata,
                label_cdata,
                outData,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(get_dptr(outData, lib.Esys_Free))

    def rsa_decrypt(
        self,
        key_handle: ESYS_TR,
        cipher_text: Union[TPM2B_PUBLIC_KEY_RSA, bytes, str],
        in_scheme: TPMT_RSA_DECRYPT,
        label: Union[TPM2B_DATA, bytes, str, None] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PUBLIC_KEY_RSA:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inScheme_cdata = get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        cipherText_cdata = get_cdata(cipher_text, TPM2B_PUBLIC_KEY_RSA, "cipher_text")
        label_cdata = get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        message = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Decrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                cipherText_cdata,
                inScheme_cdata,
                label_cdata,
                message,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(get_dptr(message, lib.Esys_Free))

    def ecdh_key_gen(
        self,
        key_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT]:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        zPoint = ffi.new("TPM2B_ECC_POINT **")
        pubPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_KeyGen(
                self._ctx, key_handle, session1, session2, session3, zPoint, pubPoint
            )
        )
        return (
            TPM2B_ECC_POINT(get_dptr(zPoint, lib.Esys_Free)),
            TPM2B_ECC_POINT(get_dptr(pubPoint, lib.Esys_Free)),
        )

    def ecdh_zgen(
        self,
        key_handle: ESYS_TR,
        in_point=TPM2B_ECC_POINT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_ECC_POINT:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPoint_cdata = get_cdata(in_point, TPM2B_ECC_POINT, "in_point")

        outPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_ZGen(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                inPoint_cdata,
                outPoint,
            )
        )
        return TPM2B_ECC_POINT(get_dptr(outPoint, lib.Esys_Free))

    def ecc_parameters(
        self,
        curve_id: TPM2_ECC_CURVE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMS_ALGORITHM_DETAIL_ECC:

        check_friendly_int(curve_id, "curve_id", TPM2_ECC_CURVE)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        parameters = ffi.new("TPMS_ALGORITHM_DETAIL_ECC **")
        _chkrc(
            lib.Esys_ECC_Parameters(
                self._ctx, session1, session2, session3, curve_id, parameters
            )
        )
        return TPMS_ALGORITHM_DETAIL_ECC(get_dptr(parameters, lib.Esys_Free))

    def zgen_2_phase(
        self,
        key_a: ESYS_TR,
        in_qs_b: TPM2B_ECC_POINT,
        in_qe_b: TPM2B_ECC_POINT,
        in_scheme: TPM2_ALG,
        counter: int,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT]:

        check_handle_type(session1, "key_a")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(in_scheme, "in_scheme", TPM2_ALG)

        if not isinstance(counter, int):
            raise TypeError(f"Expected counter to be type int, got {type(counter)}")

        if counter < 0 or counter > 65535:
            raise ValueError(
                f"Expected counter to be in range of uint16_t, got {counter}"
            )

        inQsB_cdata = get_cdata(in_qs_b, TPM2B_ECC_POINT, "in_qs_b")
        inQeB_cdata = get_cdata(in_qe_b, TPM2B_ECC_POINT, "in_qe_b")

        outZ1 = ffi.new("TPM2B_ECC_POINT **")
        outZ2 = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ZGen_2Phase(
                self._ctx,
                key_a,
                session1,
                session2,
                session3,
                inQsB_cdata,
                inQeB_cdata,
                in_scheme,
                counter,
                outZ1,
                outZ2,
            )
        )

        return (
            TPM2B_ECC_POINT(get_dptr(outZ1, lib.Esys_Free)),
            TPM2B_ECC_POINT(get_dptr(outZ2, lib.Esys_Free)),
        )

    def encrypt_decrypt(
        self,
        key_handle: ESYS_TR,
        decrypt: bool,
        mode: TPM2_ALG,
        iv_in: Union[TPM2B_IV, bytes, str],
        in_data: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_MAX_BUFFER, TPM2B_IV]:

        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(mode, "mode", TPM2_ALG)

        ivIn_cdata = get_cdata(iv_in, TPM2B_IV, "iv_in")
        inData_cdata = get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError(f"Expected decrypt to be type bool, got {type(decrypt)}")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                decrypt,
                mode,
                ivIn_cdata,
                inData_cdata,
                outData,
                ivOut,
            )
        )
        return (
            TPM2B_MAX_BUFFER(get_dptr(outData, lib.Esys_Free)),
            TPM2B_IV(get_dptr(ivOut, lib.Esys_Free)),
        )

    def encrypt_decrypt_2(
        self,
        key_handle: ESYS_TR,
        decrypt: bool,
        mode: TPM2_ALG,
        iv_in: Union[TPM2B_IV, bytes, str],
        in_data: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_MAX_BUFFER, TPM2B_IV]:

        check_handle_type(key_handle, "key_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(mode, "mode", TPM2_ALG)

        ivIn_cdata = get_cdata(iv_in, TPM2B_IV, "iv_in")
        inData_cdata = get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError("Expected decrypt to be type bool, got {type(decrypt)}")

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt2(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                inData_cdata,
                decrypt,
                mode,
                ivIn_cdata,
                outData,
                ivOut,
            )
        )
        return (
            TPM2B_MAX_BUFFER(get_dptr(outData, lib.Esys_Free)),
            TPM2B_IV(get_dptr(ivOut, lib.Esys_Free)),
        )

    def hash(
        self,
        data: Union[TPM2B_MAX_BUFFER, bytes, str],
        hash_alg: TPM2_ALG,
        hierarchy: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK]:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        data_cdata = get_cdata(data, TPM2B_MAX_BUFFER, "data")

        outHash = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_Hash(
                self._ctx,
                session1,
                session2,
                session3,
                data_cdata,
                hash_alg,
                hierarchy,
                outHash,
                validation,
            )
        )
        return (
            TPM2B_DIGEST(get_dptr(outHash, lib.Esys_Free)),
            TPMT_TK_HASHCHECK(get_dptr(validation, lib.Esys_Free)),
        )

    def hmac(
        self,
        handle: ESYS_TR,
        buffer: Union[TPM2B_MAX_BUFFER, bytes, str],
        hash_alg: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DIGEST:

        check_handle_type(handle, "handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer")

        outHMAC = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_HMAC(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                hash_alg,
                outHMAC,
            )
        )
        return TPM2B_DIGEST(get_dptr(outHMAC, lib.Esys_Free))

    def get_random(
        self,
        bytes_requested: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DIGEST:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if not isinstance(bytes_requested, int):
            raise TypeError(
                f"Expected bytes_requested type to be int, got {type(bytes_requested)}"
            )

        randomBytes = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_GetRandom(
                self._ctx, session1, session2, session3, bytes_requested, randomBytes
            )
        )

        return TPM2B_DIGEST(get_dptr(randomBytes, lib.Esys_Free))

    def stir_random(
        self,
        in_data: Union[TPM2B_SENSITIVE_DATA, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inData_cdata = get_cdata(in_data, TPM2B_SENSITIVE_DATA, "in_data")

        _chkrc(
            lib.Esys_StirRandom(self._ctx, session1, session2, session3, inData_cdata)
        )

    def hmac_start(
        self,
        handle: ESYS_TR,
        auth: Union[TPM2B_AUTH, bytes, str],
        hash_alg: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(handle, "handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth")

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HMAC_Start(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def hash_sequence_start(
        self,
        auth: Union[TPM2B_AUTH, bytes, str],
        hash_alg: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth")

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HashSequenceStart(
                self._ctx,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def sequence_update(
        self,
        sequence_handle: ESYS_TR,
        buffer: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        _chkrc(
            lib.Esys_SequenceUpdate(
                self._ctx, sequence_handle, session1, session2, session3, buffer_cdata
            )
        )

    def sequence_complete(
        self,
        sequence_handle: ESYS_TR,
        buffer: Union[TPM2B_MAX_BUFFER, bytes, str],
        hierarchy: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK]:

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(hierarchy, "hierarchy", ESYS_TR)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        result = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_SequenceComplete(
                self._ctx,
                sequence_handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                hierarchy,
                result,
                validation,
            )
        )

        return (
            TPM2B_DIGEST(get_dptr(result, lib.Esys_Free)),
            TPMT_TK_HASHCHECK(get_dptr(validation, lib.Esys_Free)),
        )

    def event_sequence_complete(
        self,
        pcr_handle: ESYS_TR,
        sequence_handle: ESYS_TR,
        buffer: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPML_DIGEST_VALUES:

        check_handle_type(sequence_handle, "sequence_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        buffer_cdata = get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

        results = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_EventSequenceComplete(
                self._ctx,
                pcr_handle,
                sequence_handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                results,
            )
        )
        return TPML_DIGEST_VALUES(get_dptr(results, lib.Esys_Free))

    def certify(
        self,
        object_handle: ESYS_TR,
        sign_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(object_handle, "object_handle")
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Certify(
                self._ctx,
                object_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                certifyInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(certifyInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def certify_creation(
        self,
        sign_handle: ESYS_TR,
        object_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        creation_hash: Union[TPM2B_DIGEST, bytes, str],
        in_scheme: TPMT_SIG_SCHEME,
        creation_ticket: TPMT_TK_CREATION,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(object_handle, "object_handle")
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        creationHash_cdata = get_cdata(creation_hash, TPM2B_DIGEST, "creation_hash")
        creationTicket_cdata = get_cdata(
            creation_ticket, TPMT_TK_CREATION, "creation_ticket"
        )

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_CertifyCreation(
                self._ctx,
                sign_handle,
                object_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                creationHash_cdata,
                inScheme_cdata,
                creationTicket_cdata,
                certifyInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(certifyInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def quote(
        self,
        sign_handle: ESYS_TR,
        pcr_select: Union[TPML_PCR_SELECTION, str],
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        PCRselect_cdata = get_cdata(pcr_select, TPML_PCR_SELECTION, "pcr_select")

        quoted = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Quote(
                self._ctx,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                PCRselect_cdata,
                quoted,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(quoted, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def get_session_audit_digest(
        self,
        sign_handle: ESYS_TR,
        session_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle: ESYS_TR = ESYS_TR.RH_ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(session_handle, "session_handle")
        check_handle_type(
            privacy_admin_handle,
            "privacy_admin_handle",
            expected=[ESYS_TR.RH_ENDORSEMENT],
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetSessionAuditDigest(
                self._ctx,
                privacy_admin_handle,
                sign_handle,
                session_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                auditInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(auditInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def get_command_audit_digest(
        self,
        sign_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_handle: ESYS_TR = ESYS_TR.RH_ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(
            privacy_handle, "privacy_handle", expected=[ESYS_TR.RH_ENDORSEMENT]
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetCommandAuditDigest(
                self._ctx,
                privacy_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                auditInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(auditInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def get_time(
        self,
        sign_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle: ESYS_TR = ESYS_TR.RH_ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        check_handle_type(
            privacy_admin_handle, "privacy_admin_handle", expected=[ESYS_TR.ENDORSEMENT]
        )
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        timeInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetTime(
                self._ctx,
                privacy_admin_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                timeInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(timeInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def commit(
        self,
        sign_handle: ESYS_TR,
        p1: TPM2B_ECC_POINT,
        s2: Union[TPM2B_SENSITIVE_DATA, bytes, str],
        y2: Union[TPM2B_ECC_PARAMETER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT, TPM2B_ECC_POINT, int]:

        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        P1_cdata = get_cdata(p1, TPM2B_ECC_POINT, "p1")
        s2_cdata = get_cdata(s2, TPM2B_SENSITIVE_DATA, "s2")
        y2_cdata = get_cdata(y2, TPM2B_ECC_PARAMETER, "y2")

        K = ffi.new("TPM2B_ECC_POINT **")
        L = ffi.new("TPM2B_ECC_POINT **")
        E = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_Commit(
                self._ctx,
                sign_handle,
                session1,
                session2,
                session3,
                P1_cdata,
                s2_cdata,
                y2_cdata,
                K,
                L,
                E,
                counter,
            )
        )
        return (
            TPM2B_ECC_POINT(get_dptr(K, lib.Esys_Free)),
            TPM2B_ECC_POINT(get_dptr(L, lib.Esys_Free)),
            TPM2B_ECC_POINT(get_dptr(E, lib.Esys_Free)),
            counter[0],
        )

    def ec_ephemeral(
        self,
        curve_id: TPM2_ECC_CURVE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT, int]:

        check_friendly_int(curve_id, "curve_id", TPM2_ECC_CURVE)
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        Q = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_EC_Ephemeral(
                self._ctx, session1, session2, session3, curve_id, Q, counter
            )
        )
        return (TPM2B_ECC_POINT(get_dptr(Q, lib.Esys_Free)), counter[0])

    def verify_signature(
        self,
        key_handle: ESYS_TR,
        digest: Union[TPM2B_DIGEST, bytes, int],
        signature: TPMT_SIGNATURE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMT_TK_VERIFIED:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        digest_cdata = get_cdata(digest, TPM2B_DIGEST, "digest")
        signature_cdata = get_cdata(signature, TPMT_SIGNATURE, "signature")

        validation = ffi.new("TPMT_TK_VERIFIED **")
        _chkrc(
            lib.Esys_VerifySignature(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                digest_cdata,
                signature_cdata,
                validation,
            )
        )
        return TPMT_TK_VERIFIED(get_dptr(validation, lib.Esys_Free))

    def sign(
        self,
        key_handle: ESYS_TR,
        digest: Union[TPM2B_DIGEST, bytes, str],
        in_scheme: TPMT_SIG_SCHEME,
        validation: TPMT_TK_HASHCHECK,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMT_SIGNATURE:

        check_handle_type(key_handle, "key_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        digest_cdata = get_cdata(digest, TPM2B_DIGEST, "digest")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        validation_cdata = get_cdata(validation, TPMT_TK_HASHCHECK, "validation")

        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Sign(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                digest_cdata,
                inScheme_cdata,
                validation_cdata,
                signature,
            )
        )
        return TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free))

    def set_command_code_audit_status(
        self,
        audit_alg: TPM2_ALG,
        set_list: TPML_CC,
        clear_list: TPML_CC,
        auth: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth, "auth", expected=[ESYS_TR.OWNER, ESYS_TR.PLATFORM])

        check_friendly_int(audit_alg, "audit_alg", TPM2_ALG)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        setList_cdata = get_cdata(set_list, TPML_CC, "set_list")
        clearList_cdata = get_cdata(clear_list, TPML_CC, "digest")

        _chkrc(
            lib.Esys_SetCommandCodeAuditStatus(
                self._ctx,
                auth,
                session1,
                session2,
                session3,
                audit_alg,
                setList_cdata,
                clearList_cdata,
            )
        )

    def pcr_extend(
        self,
        pcr_handle: ESYS_TR,
        digests: TPML_DIGEST_VALUES,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(pcr_handle, "pcr_handle")

        digests_cdata = get_cdata(digests, TPML_DIGEST_VALUES, "digests")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_Extend(
                self._ctx, pcr_handle, session1, session2, session3, digests_cdata
            )
        )

    def pcr_event(
        self,
        pcr_handle: ESYS_TR,
        event_data: Union[TPM2B_EVENT, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPML_DIGEST_VALUES:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        check_handle_type(pcr_handle, "pcr_handle")

        eventData_cdata = get_cdata(event_data, TPM2B_EVENT, "event_data")

        digests = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_PCR_Event(
                self._ctx,
                pcr_handle,
                session1,
                session2,
                session3,
                eventData_cdata,
                digests,
            )
        )
        return TPML_DIGEST_VALUES(get_dptr(digests, lib.Esys_Free))

    def pcr_read(
        self,
        pcr_selection_in: Union[TPML_PCR_SELECTION, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[int, TPML_PCR_SELECTION, TPML_DIGEST]:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrSelectionIn_cdata = get_cdata(
            pcr_selection_in, TPML_PCR_SELECTION, "pcr_selection_in"
        )

        pcrUpdateCounter = ffi.new("UINT32 *")
        pcrSelectionOut = ffi.new("TPML_PCR_SELECTION **")
        pcrValues = ffi.new("TPML_DIGEST **")
        _chkrc(
            lib.Esys_PCR_Read(
                self._ctx,
                session1,
                session2,
                session3,
                pcrSelectionIn_cdata,
                pcrUpdateCounter,
                pcrSelectionOut,
                pcrValues,
            )
        )

        return (
            pcrUpdateCounter[0],
            TPML_PCR_SELECTION(_cdata=get_dptr(pcrSelectionOut, lib.Esys_Free)),
            TPML_DIGEST(_cdata=get_dptr(pcrValues, lib.Esys_Free)),
        )

    def pcr_allocate(
        self,
        pcr_allocation: Union[TPML_PCR_SELECTION, str],
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[bool, int, int, int]:

        check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrAllocation_cdata = get_cdata(
            pcr_allocation, TPML_PCR_SELECTION, "pcr_allocation"
        )

        allocationSuccess = ffi.new("TPMI_YES_NO *")
        maxPCR = ffi.new("UINT32 *")
        sizeNeeded = ffi.new("UINT32 *")
        sizeAvailable = ffi.new("UINT32 *")
        _chkrc(
            lib.Esys_PCR_Allocate(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                pcrAllocation_cdata,
                allocationSuccess,
                maxPCR,
                sizeNeeded,
                sizeAvailable,
            )
        )
        return (bool(allocationSuccess[0]), maxPCR[0], sizeNeeded[0], sizeAvailable[0])

    def pcr_set_auth_policy(
        self,
        auth_policy: Union[TPM2B_DIGEST, bytes, str],
        hash_alg: TPM2_ALG,
        pcr_num: ESYS_TR,
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])

        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)
        check_friendly_int(pcr_num, "pcr_num", ESYS_TR)

        authPolicy_cdata = get_cdata(auth_policy, TPM2B_DIGEST, "auth_policy")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_SetAuthPolicy(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                authPolicy_cdata,
                hash_alg,
                pcr_num,
            )
        )

    def pcr_set_auth_value(
        self,
        pcr_handle: ESYS_TR,
        auth: Union[TPM2B_DIGEST, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        auth_cdata = get_cdata(auth, TPM2B_DIGEST, "auth")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_SetAuthValue(
                self._ctx, pcr_handle, session1, session2, session3, auth_cdata
            )
        )

    def pcr_reset(
        self,
        pcr_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_PCR_Reset(self._ctx, pcr_handle, session1, session2, session3))

    def policy_signed(
        self,
        auth_object: ESYS_TR,
        policy_session: ESYS_TR,
        nonce_tpm: Union[TPM2B_NONCE, bytes, str],
        cp_hash_a: Union[TPM2B_DIGEST, bytes, str],
        policy_ref: Union[TPM2B_NONCE, bytes, str],
        expiration: int,
        auth: TPMT_SIGNATURE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH]:

        check_handle_type(auth_object, "auth_object")

        check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        nonceTPM_cdata = get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        auth_cdata = get_cdata(auth, TPMT_SIGNATURE, "auth")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySigned(
                self._ctx,
                auth_object,
                policy_session,
                session1,
                session2,
                session3,
                nonceTPM_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                expiration,
                auth_cdata,
                timeout,
                policyTicket,
            )
        )
        return (
            TPM2B_TIMEOUT(get_dptr(timeout, lib.Esys_Free)),
            TPMT_TK_AUTH(get_dptr(policyTicket, lib.Esys_Free)),
        )

    def policy_secret(
        self,
        auth_handle: ESYS_TR,
        policy_session: ESYS_TR,
        nonce_tpm: Union[TPM2B_NONCE, bytes, str],
        cp_hash_a: Union[TPM2B_DIGEST, bytes, str],
        policy_ref: Union[TPM2B_NONCE, bytes, str],
        expiration: int,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH]:

        check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        check_friendly_int(auth_handle, "auth_handle", ESYS_TR)

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        nonceTPM_cdata = get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySecret(
                self._ctx,
                auth_handle,
                policy_session,
                session1,
                session2,
                session3,
                nonceTPM_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                expiration,
                timeout,
                policyTicket,
            )
        )
        return (
            TPM2B_TIMEOUT(get_dptr(timeout, lib.Esys_Free)),
            TPMT_TK_AUTH(get_dptr(policyTicket, lib.Esys_Free)),
        )

    def policy_ticket(
        self,
        policy_session: ESYS_TR,
        timeout: TPM2B_TIMEOUT,
        cp_hash_a: Union[TPM2B_DIGEST, bytes, str],
        policy_ref: Union[TPM2B_NONCE, bytes, str],
        auth_name: Union[TPM2B_NAME, bytes, str],
        ticket: TPMT_TK_AUTH,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        timeout_cdata = get_cdata(timeout, TPM2B_TIMEOUT, "timeout")
        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        authName_cdata = get_cdata(auth_name, TPM2B_NAME, "auth_name")
        ticket_cdata = get_cdata(ticket, TPMT_TK_AUTH, "ticket")

        _chkrc(
            lib.Esys_PolicyTicket(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                timeout_cdata,
                cpHashA_cdata,
                policyRef_cdata,
                authName_cdata,
                ticket_cdata,
            )
        )

    def policy_or(
        self,
        policy_session: ESYS_TR,
        p_hash_list: TPML_DIGEST,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pHashList_cdata = get_cdata(p_hash_list, TPML_DIGEST, "p_hash_list")

        _chkrc(
            lib.Esys_PolicyOR(
                self._ctx, policy_session, session1, session2, session3, pHashList_cdata
            )
        )

    def policy_pcr(
        self,
        policy_session: ESYS_TR,
        pcr_digest: Union[TPM2B_DIGEST, bytes, str],
        pcrs: Union[TPML_PCR_SELECTION, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        pcrDigest_cdata = get_cdata(pcr_digest, TPM2B_DIGEST, "pcr_digest")
        pcrs_cdata = get_cdata(pcrs, TPML_PCR_SELECTION, "pcrs")

        _chkrc(
            lib.Esys_PolicyPCR(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                pcrDigest_cdata,
                pcrs_cdata,
            )
        )

    def policy_locality(
        self,
        policy_session: ESYS_TR,
        locality: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if not isinstance(locality, int):
            raise TypeError(
                f"Expected locality to be of type TPMA_LOCALITY aka int, got {type(locality)}"
            )

        # Locality of 0-4 are indicated as bit index 0-4 being set. Localities 32-255 are
        # indicated as values. Thus locality of 0 is invalid, along with values greater than
        # 1 byte (255).
        if locality < 1 or locality > 255:
            raise ValueError(
                f"Expected locality to be in range of 1 - 255, got {locality}"
            )

        _chkrc(
            lib.Esys_PolicyLocality(
                self._ctx, policy_session, session1, session2, session3, locality
            )
        )

    def policy_nv(
        self,
        auth_handle: ESYS_TR,
        nv_index: ESYS_TR,
        policy_session: ESYS_TR,
        operand_b: TPM2B_OPERAND,
        operation: TPM2_EO,
        offset: int = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_friendly_int(auth_handle, "auth_handle", ESYS_TR)
        check_handle_type(nv_index, "nv_index")

        check_handle_type(policy_session, "policy_session")

        operandB_cdata = get_cdata(operand_b, TPM2B_OPERAND, "operand_b")

        check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNV(
                self._ctx,
                auth_handle,
                nv_index,
                policy_session,
                session1,
                session2,
                session3,
                operandB_cdata,
                offset,
                operation,
            )
        )

    def policy_counter_timer(
        self,
        policy_session: ESYS_TR,
        operand_b: TPM2B_OPERAND,
        operation: TPM2_EO,
        offset: int = 0,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        operandB_cdata = get_cdata(operand_b, TPM2B_OPERAND, "operand_b")

        check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCounterTimer(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                operandB_cdata,
                offset,
                operation,
            )
        )

    def policy_command_code(
        self,
        policy_session: ESYS_TR,
        code: TPM2_CC,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        check_friendly_int(code, "code", TPM2_CC)

        _chkrc(
            lib.Esys_PolicyCommandCode(
                self._ctx, policy_session, session1, session2, session3, code
            )
        )

    def policy_physical_presence(
        self,
        policy_session: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyPhysicalPresence(
                self._ctx, policy_session, session1, session2, session3
            )
        )

    def policy_cp_hash(
        self,
        policy_session: ESYS_TR,
        cp_hash_a: Union[TPM2B_DIGEST, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        cpHashA_cdata = get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCpHash(
                self._ctx, policy_session, session1, session2, session3, cpHashA_cdata
            )
        )

    def policy_name_hash(
        self,
        policy_session: ESYS_TR,
        name_hash: Union[TPM2B_DIGEST, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        nameHash_cdata = get_cdata(name_hash, TPM2B_DIGEST, "name_hash")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNameHash(
                self._ctx, policy_session, session1, session2, session3, nameHash_cdata
            )
        )

    def policy_duplication_select(
        self,
        policy_session: ESYS_TR,
        object_name: Union[TPM2B_NAME, bytes, str],
        new_parent_name: Union[TPM2B_NAME, bytes, str],
        include_object: bool = False,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        objectName_cdata = get_cdata(object_name, TPM2B_NAME, "object_name")
        newParentName_cdata = get_cdata(new_parent_name, TPM2B_NAME, "new_parent_name")

        if not isinstance(include_object, bool):
            raise TypeError(
                f"Expected include_object to be type bool, got {type(include_object)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyDuplicationSelect(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                objectName_cdata,
                newParentName_cdata,
                include_object,
            )
        )

    def policy_authorize(
        self,
        policy_session: ESYS_TR,
        approved_policy: Union[TPM2B_DIGEST, bytes, str],
        policy_ref: Union[TPM2B_NONCE, bytes, str],
        key_sign: Union[TPM2B_NAME, bytes, str],
        check_ticket: TPMT_TK_VERIFIED,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        approvedPolicy_cdata = get_cdata(
            approved_policy, TPM2B_DIGEST, "approved_policy"
        )
        policyRef_cdata = get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        keySign_cdata = get_cdata(key_sign, TPM2B_NAME, "key_sign")
        checkTicket_cdata = get_cdata(check_ticket, TPMT_TK_VERIFIED, "check_ticket")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthorize(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                approvedPolicy_cdata,
                policyRef_cdata,
                keySign_cdata,
                checkTicket_cdata,
            )
        )

    def policy_auth_value(
        self,
        policy_session: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthValue(
                self._ctx, policy_session, session1, session2, session3
            )
        )

    def policy_password(
        self,
        policy_session: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyPassword(
                self._ctx, policy_session, session1, session2, session3
            )
        )

    def policy_get_digest(
        self,
        policy_session: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        policyDigest = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_PolicyGetDigest(
                self._ctx, policy_session, session1, session2, session3, policyDigest
            )
        )
        return TPM2B_DIGEST(get_dptr(policyDigest, lib.Esys_Free))

    def policy_nv_written(
        self,
        policy_session: ESYS_TR,
        written_set: bool = True,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        if not isinstance(written_set, bool):
            raise TypeError(
                f"Expected written_set to be type bool, got {type(written_set)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNvWritten(
                self._ctx, policy_session, session1, session2, session3, written_set
            )
        )

    def policy_template(
        self,
        policy_session: ESYS_TR,
        template_hash: Union[TPM2B_DIGEST, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(policy_session, "policy_session")

        templateHash_cdata = get_cdata(template_hash, TPM2B_DIGEST, "template_hash")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyTemplate(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                templateHash_cdata,
            )
        )

    def policy_authorize_nv(
        self,
        nv_index: ESYS_TR,
        policy_session: ESYS_TR,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(policy_session, "policy_session")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthorizeNV(
                self._ctx,
                auth_handle,
                nv_index,
                policy_session,
                session1,
                session2,
                session3,
            )
        )

    def create_primary(
        self,
        in_sensitive: TPM2B_SENSITIVE_CREATE,
        in_public: Union[TPM2B_PUBLIC, str] = "rsa2048",
        primary_handle: ESYS_TR = ESYS_TR.OWNER,
        outside_info: Union[TPM2B_DATA, bytes, str] = TPM2B_DATA(),
        creation_pcr: Union[TPML_PCR_SELECTION, str] = TPML_PCR_SELECTION(),
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPMT_TK_CREATION]:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        inPublic_cdata = get_cdata(
            in_public,
            TPM2B_PUBLIC,
            "in_public",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )
        inSensitive_cdata = get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        outsideInfo_cdata = get_cdata(outside_info, TPM2B_DATA, "outside_info")
        creationPCR_cdata = get_cdata(creation_pcr, TPML_PCR_SELECTION, "creation_pcr")

        objectHandle = ffi.new("ESYS_TR *")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_CreatePrimary(
                self._ctx,
                primary_handle,
                session1,
                session2,
                session3,
                inSensitive_cdata,
                inPublic_cdata,
                outsideInfo_cdata,
                creationPCR_cdata,
                objectHandle,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )

        return (
            ESYS_TR(objectHandle[0]),
            TPM2B_PUBLIC(_cdata=get_dptr(outPublic, lib.Esys_Free)),
            TPM2B_CREATION_DATA(_cdata=get_dptr(creationData, lib.Esys_Free)),
            TPM2B_DIGEST(_cdata=get_dptr(creationHash, lib.Esys_Free)),
            TPMT_TK_CREATION(_cdata=get_dptr(creationTicket, lib.Esys_Free)),
        )

    def hierarchy_control(
        self,
        auth_handle: ESYS_TR,
        enable: ESYS_TR,
        state: bool,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )
        check_handle_type(
            enable,
            "enable",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )

        if not isinstance(state, bool):
            raise TypeError(f"Expected state to be a bool, got {type(state)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_HierarchyControl(
                self._ctx, auth_handle, session1, session2, session3, enable, state
            )
        )

    def set_primary_policy(
        self,
        auth_handle: ESYS_TR,
        auth_policy: Union[TPM2B_DIGEST, bytes, str],
        hash_alg: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_OWNER, ESYS_TR.RH_PLATFORM),
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        authPolicy_cdata = get_cdata(auth_policy, TPM2B_DIGEST, "auth_policy")
        check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        _chkrc(
            lib.Esys_SetPrimaryPolicy(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                authPolicy_cdata,
                hash_alg,
            )
        )

    def change_pps(
        self,
        auth_handle: ESYS_TR = ESYS_TR.RH_PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle", expected=(ESYS_TR.RH_PLATFORM,))

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangePPS(self._ctx, auth_handle, session1, session2, session3))

    def change_eps(
        self,
        auth_handle: ESYS_TR = ESYS_TR.RH_PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle", expected=(ESYS_TR.RH_PLATFORM,))

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangeEPS(self._ctx, auth_handle, session1, session2, session3))

    def clear(
        self,
        auth_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(ESYS_TR.RH_PLATFORM, ESYS_TR.RH_LOCKOUT),
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(lib.Esys_Clear(self._ctx, auth_handle, session1, session2, session3))

    def clear_control(
        self,
        auth: ESYS_TR,
        disable: bool,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(
            auth, "auth", expected=(ESYS_TR.RH_PLATFORM, ESYS_TR.RH_LOCKOUT)
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        if not isinstance(disable, bool):
            raise TypeError(f"Expected disable to be a bool, got {type(disable)}")

        _chkrc(
            lib.Esys_ClearControl(
                self._ctx, auth, session1, session2, session3, disable
            )
        )

    def hierarchy_change_auth(
        self,
        auth_handle: ESYS_TR,
        new_auth: Union[TPM2B_AUTH, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        new_auth_cdata = get_cdata(new_auth, TPM2B_AUTH, "new_auth")

        _chkrc(
            lib.Esys_HierarchyChangeAuth(
                self._ctx, auth_handle, session1, session2, session3, new_auth_cdata,
            )
        )

    def dictionary_attack_lock_reset(
        self,
        lock_handle: ESYS_TR = ESYS_TR.RH_LOCKOUT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(lock_handle, "lock_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_DictionaryAttackLockReset(
                self._ctx, lock_handle, session1, session2, session3
            )
        )

    def dictionary_attack_parameters(
        self,
        new_max_tries: int,
        new_recovery_time: int,
        lockout_recovery: int,
        lock_handle=ESYS_TR.RH_LOCKOUT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if not isinstance(new_max_tries, int):
            raise TypeError(
                f"Expected new_max_tries to be an int, got {type(new_max_tries)}"
            )

        if not isinstance(new_recovery_time, int):
            raise TypeError(
                f"Expected new_recovery_time to be an int, got {type(new_recovery_time)}"
            )

        if not isinstance(lockout_recovery, int):
            raise TypeError(
                f"Expected lockout_recovery to be an int, got {type(lockout_recovery)}"
            )

        check_handle_type(lock_handle, "lock_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_DictionaryAttackParameters(
                self._ctx,
                lock_handle,
                session1,
                session2,
                session3,
                new_max_tries,
                new_recovery_time,
                lockout_recovery,
            )
        )

    def pp_commands(
        self,
        set_list: TPML_CC,
        clear_list: TPML_CC,
        auth: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth, "auth")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        setList_cdata = get_cdata(set_list, TPML_CC, "set_list")
        clearList_cdata = get_cdata(clear_list, TPML_CC, "clear_list")
        _chkrc(
            lib.Esys_PP_Commands(
                self._ctx,
                auth,
                session1,
                session2,
                session3,
                setList_cdata,
                clearList_cdata,
            )
        )

    def set_algorithm_set(
        self,
        algorithm_set: Union[List[int], int],
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_SetAlgorithmSet(
                self._ctx, auth_handle, session1, session2, session3, algorithm_set
            )
        )

    def field_upgrade_start(
        self,
        authorization: ESYS_TR,
        key_handle: ESYS_TR,
        fu_digest: Union[TPM2B_DIGEST, bytes, str],
        manifest_signature: TPMT_SIGNATURE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(authorization, "authorization")
        check_handle_type(key_handle, "key_handle")
        fuDigest_cdata = get_cdata(fu_digest, TPM2B_DIGEST, "fu_digest")
        manifestSignature_cdata = get_cdata(
            manifest_signature, TPMT_SIGNATURE, "manifest_signature"
        )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_FieldUpgradeStart(
                self._ctx,
                authorization,
                key_handle,
                session1,
                session2,
                session3,
                fuDigest_cdata,
                manifestSignature_cdata,
            )
        )

    def field_upgrade_data(
        self,
        fu_data: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPMT_HA, TPMT_HA]:

        fuData_cdata = get_cdata(fu_data, TPM2B_MAX_BUFFER, "fu_data")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        nextDigest = ffi.new("TPMT_HA **")
        firstDigest = ffi.new("TPMT_HA **")
        _chkrc(
            lib.Esys_FieldUpgradeData(
                self._ctx,
                session1,
                session2,
                session3,
                fuData_cdata,
                nextDigest,
                firstDigest,
            )
        )
        return (
            TPMT_HA(get_dptr(nextDigest, lib.Esys_Free)),
            TPMT_HA(get_dptr(firstDigest, lib.Esys_Free)),
        )

    def firmware_read(
        self,
        sequence_number: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        if not isinstance(sequence_number, int):
            raise TypeError(
                f"Expected sequence_number to be an int, got {type(sequence_number)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        fuData = ffi.new("TPM2B_MAX_BUFFER **")
        _chkrc(
            lib.Esys_FirmwareRead(
                self._ctx, session1, session2, session3, sequence_number, fuData
            )
        )
        return TPM2B_MAX_BUFFER(get_dptr(fuData, lib.Esys_Free))

    def context_save(self, save_handle: ESYS_TR) -> TPMS_CONTEXT:
        check_handle_type(save_handle, "save_handle")
        context = ffi.new("TPMS_CONTEXT **")
        _chkrc(lib.Esys_ContextSave(self._ctx, save_handle, context))
        return TPMS_CONTEXT(get_dptr(context, lib.Esys_Free))

    def context_load(self, context: TPMS_CONTEXT) -> ESYS_TR:
        context_cdata = get_cdata(context, TPMS_CONTEXT, "context")
        loadedHandle = ffi.new("ESYS_TR *")
        _chkrc(lib.Esys_ContextLoad(self._ctx, context_cdata, loadedHandle))
        loadedHandleObject = loadedHandle[0]
        return loadedHandleObject

    def flush_context(self, flush_handle: ESYS_TR) -> None:
        check_handle_type(flush_handle, "flush_handle")
        _chkrc(lib.Esys_FlushContext(self._ctx, flush_handle))

    def evict_control(
        self,
        auth: ESYS_TR,
        object_handle,
        persistent_handle: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(auth, "auth")
        check_handle_type(object_handle, "object_handle")
        check_handle_type(persistent_handle, "persistent_handle")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        newObjectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_EvictControl(
                self._ctx,
                auth,
                object_handle,
                session1,
                session2,
                session3,
                persistent_handle,
                newObjectHandle,
            )
        )
        newObjectHandleObject = newObjectHandle[0]
        return newObjectHandleObject

    def read_clock(
        self,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMS_TIME_INFO:

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        currentTime = ffi.new("TPMS_TIME_INFO **")
        _chkrc(lib.Esys_ReadClock(self._ctx, session1, session2, session3, currentTime))
        return TPMS_TIME_INFO(get_dptr(currentTime, lib.Esys_Free))

    def clock_set(
        self,
        auth: ESYS_TR,
        new_time: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):

        check_handle_type(auth, "auth")

        if not isinstance(new_time, int):
            raise TypeError(f"Expected new_time to be an int, got {type(new_time)}")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_ClockSet(self._ctx, auth, session1, session2, session3, new_time)
        )

    def clock_rate_adjust(
        self,
        auth: ESYS_TR,
        rate_adjust: TPM2_CLOCK,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth, "auth")

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_ClockRateAdjust(
                self._ctx, auth, session1, session2, session3, rate_adjust
            )
        )

    def get_capability(
        self,
        capability: TPM2_CAP,
        prop: int,
        property_count: int = 1,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[bool, TPMS_CAPABILITY_DATA]:

        check_friendly_int(capability, "capability", TPM2_CAP)

        if not isinstance(prop, int):
            raise TypeError(f"Expected prop to be an int, got {type(prop)}")

        if not isinstance(property_count, int):
            raise TypeError(
                f"Expected property_count to be an int, got {type(property_count)}"
            )

        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        moreData = ffi.new("TPMI_YES_NO *")
        capabilityData = ffi.new("TPMS_CAPABILITY_DATA **")
        _chkrc(
            lib.Esys_GetCapability(
                self._ctx,
                session1,
                session2,
                session3,
                capability,
                prop,
                property_count,
                moreData,
                capabilityData,
            )
        )
        return (
            bool(moreData[0]),
            TPMS_CAPABILITY_DATA(get_dptr(capabilityData, lib.Esys_Free)),
        )

    def test_parms(
        self,
        parameters: TPMT_PUBLIC_PARMS,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        parameters_cdata = get_cdata(parameters, TPMT_PUBLIC_PARMS, "parameters")
        _chkrc(
            lib.Esys_TestParms(
                self._ctx, session1, session2, session3, parameters_cdata
            )
        )

    def nv_define_space(
        self,
        auth: ESYS_TR,
        public_info: TPM2B_NV_PUBLIC,
        auth_handle: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth", allow_none=True)
        publicInfo_cdata = get_cdata(public_info, TPM2B_NV_PUBLIC, "public_info")
        nvHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_NV_DefineSpace(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                auth_cdata,
                publicInfo_cdata,
                nvHandle,
            )
        )
        nvHandleObject = nvHandle[0]
        return nvHandleObject

    def nv_undefine_space(
        self,
        nv_index: ESYS_TR,
        auth_handle: ESYS_TR = ESYS_TR.RH_OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_UndefineSpace(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_undefine_space_special(
        self,
        nv_index: ESYS_TR,
        platform: ESYS_TR = ESYS_TR.RH_PLATFORM,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(nv_index, "nv_index")
        check_handle_type(platform, "platform")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_UndefineSpaceSpecial(
                self._ctx, nv_index, platform, session1, session2, session3
            )
        )

    def nv_read_public(
        self,
        nv_index: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_NV_PUBLIC, TPM2B_NAME]:

        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        nvPublic = ffi.new("TPM2B_NV_PUBLIC **")
        nvName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_NV_ReadPublic(
                self._ctx, nv_index, session1, session2, session3, nvPublic, nvName
            )
        )
        return (
            TPM2B_NV_PUBLIC(_cdata=get_dptr(nvPublic, lib.Esys_Free)),
            TPM2B_NAME(_cdata=get_dptr(nvName, lib.Esys_Free)),
        )

    def nv_write(
        self,
        nv_index: ESYS_TR,
        data: Union[TPM2B_MAX_NV_BUFFER, bytes, str],
        offset: int = 0,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(nv_index, "nv_index")
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Write(
                self._ctx,
                auth_handle,
                nv_index,
                session1,
                session2,
                session3,
                data_cdata,
                offset,
            )
        )

    def nv_increment(
        self,
        nv_index: ESYS_TR,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_Increment(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_extend(
        self,
        nv_index: ESYS_TR,
        data: Union[TPM2B_MAX_NV_BUFFER, bytes, str],
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Extend(
                self._ctx,
                auth_handle,
                nv_index,
                session1,
                session2,
                session3,
                data_cdata,
            )
        )

    def nv_set_bits(
        self,
        nv_index: ESYS_TR,
        bits: int,
        auth_handle=0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index

        check_handle_type(auth_handle, "auth_handle")

        if not isinstance(bits, int):
            raise TypeError(f"Expected bits to be an int, got {type(bits)}")

        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_SetBits(
                self._ctx, auth_handle, nv_index, session1, session2, session3, bits
            )
        )

    def nv_write_lock(
        self,
        nv_index: ESYS_TR,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_WriteLock(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_global_write_lock(
        self,
        auth_handle: ESYS_TR = ESYS_TR.RH_OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_GlobalWriteLock(
                self._ctx, auth_handle, session1, session2, session3
            )
        )

    def nv_read(
        self,
        nv_index: ESYS_TR,
        size: int,
        offset: int = 0,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_MAX_NV_BUFFER:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(nv_index, "nv_index")

        if not isinstance(size, int):
            raise TypeError(f"Expected size to be an int, got {type(size)}")

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be an int, got {type(offset)}")

        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        data = ffi.new("TPM2B_MAX_NV_BUFFER **")
        _chkrc(
            lib.Esys_NV_Read(
                self._ctx,
                auth_handle,
                nv_index,
                session1,
                session2,
                session3,
                size,
                offset,
                data,
            )
        )
        return TPM2B_MAX_NV_BUFFER(get_dptr(data, lib.Esys_Free))

    def nv_read_lock(
        self,
        nv_index: ESYS_TR,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(nv_index, "nv_index")
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_ReadLock(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_change_auth(
        self,
        nv_index: ESYS_TR,
        new_auth: Union[TPM2B_DIGEST, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:

        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        newAuth_cdata = get_cdata(new_auth, TPM2B_DIGEST, "new_auth")
        _chkrc(
            lib.Esys_NV_ChangeAuth(
                self._ctx, nv_index, session1, session2, session3, newAuth_cdata
            )
        )

    def nv_certify(
        self,
        sign_handle: ESYS_TR,
        nv_index: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME,
        size: int,
        offset: int = 0,
        auth_handle: ESYS_TR = 0,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:

        if auth_handle == 0:
            auth_handle = nv_index
        check_handle_type(sign_handle, "sign_handle")
        check_handle_type(auth_handle, "auth_handle")
        check_handle_type(nv_index, "nv_index")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")
        qualifyingData_cdata = get_cdata(qualifying_data, TPM2B_DATA, "qualifying_data")
        inScheme_cdata = get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        if not isinstance(size, int):
            raise TypeError(f"Expected size to be of type int, got: {type(size)}")

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got: {type(offset)}")

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_NV_Certify(
                self._ctx,
                sign_handle,
                auth_handle,
                nv_index,
                session1,
                session2,
                session3,
                qualifyingData_cdata,
                inScheme_cdata,
                size,
                offset,
                certifyInfo,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(get_dptr(certifyInfo, lib.Esys_Free)),
            TPMT_SIGNATURE(get_dptr(signature, lib.Esys_Free)),
        )

    def vendor_tcg_test(
        self,
        input_data: Union[TPM2B_DATA, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DATA:
        inputData_cdata = get_cdata(input_data, TPM2B_DATA, "input_data")
        outputData = ffi.new("TPM2B_DATA **")
        _chkrc(
            lib.Esys_Vendor_TCG_Test(
                self._ctx, session1, session2, session3, inputData_cdata, outputData
            )
        )
        return TPM2B_DATA(get_dptr(outputData, lib.Esys_Free))

    def load_blob(self, data: bytes, type_: int = lib.FAPI_ESYSBLOB_CONTEXTLOAD) -> int:
        """load binary ESAPI object as binary blob. Supported are the types :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD` and :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_DESERIALIZE`.

        Args:
            data (bytes): Binary blob of the ESAPI object to load.
            type_ (int, optional): :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD` or :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_DESERIALIZE`. Defaults to :const:`._libtpm2_pytss.lib.FAPI_ESYSBLOB_CONTEXTLOAD`.

        Returns:
            int: The ESAPI handle to the loaded object.
        """
        esys_handle = ffi.new("ESYS_TR *")
        if type_ == lib.FAPI_ESYSBLOB_CONTEXTLOAD:
            offs = ffi.new("size_t *", 0)
            key_ctx = ffi.new("TPMS_CONTEXT *")
            _chkrc(lib.Tss2_MU_TPMS_CONTEXT_Unmarshal(data, len(data), offs, key_ctx))
            _chkrc(lib.Esys_ContextLoad(self._ctx, key_ctx, esys_handle))
        elif type_ == lib.FAPI_ESYSBLOB_DESERIALIZE:
            _chkrc(lib.Esys_TR_Deserialize(self._ctx, data, len(data), esys_handle))

        return esys_handle[0]
