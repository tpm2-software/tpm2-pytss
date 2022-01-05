# SPDX-License-Identifier: BSD-2
import pkgconfig

from .types import *
from .constants import *
from .internal.utils import _chkrc, _get_dptr, _check_friendly_int, _fixup_classname
from .TCTI import TCTI
from .TCTILdr import TCTILdr

from typing import List, Optional, Tuple, Union

# Work around this FAPI dependency if FAPI is not present with the constant value
_fapi_installed_ = pkgconfig.installed("tss2-fapi", ">=3.0.0")
_DEFAULT_LOAD_BLOB_SELECTOR = FAPI_ESYSBLOB.CONTEXTLOAD if _fapi_installed_ else 1


def _get_cdata(value, expected, varname, allow_none=False, *args, **kwargs):
    tname = expected.__name__

    if value is None and allow_none:
        return ffi.NULL
    elif value is None:
        raise TypeError(f"expected {varname} to be {tname}, got None")

    if isinstance(value, ffi.CData):
        tipe = ffi.typeof(value)
        if tipe.kind == "pointer":
            tipe = tipe.item
        classname = _fixup_classname(tipe)
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


def _check_handle_type(handle, varname, expected=None):
    if not isinstance(handle, ESYS_TR):
        raise TypeError(f"expected {varname} to be type ESYS_TR, got {type(handle)}")

    if expected is not None and handle not in expected:
        if len(expected) > 1:
            msg = f"expected {varname} to be one of {','.join([ESYS_TR.to_string(x) for x in expected])}, got {ESYS_TR.to_string(handle)}"
        else:
            msg = f"expected {varname} to be {ESYS_TR.to_string(expected[0])}, got {ESYS_TR.to_string(handle)}"

        raise ValueError(msg)


class ESAPI:
    """Initialize an ESAPI object for further use.

    Initialize an ESAPI object that holds all the state and metadata information
    during an interaction with the TPM.
    If tcti is None (the default), load a TCTI in this order:

        - Library libtss2-tcti-default.so (link to the preferred TCTI)

        - Library libtss2-tcti-tabrmd.so (tabrmd)

        - Device /dev/tpmrm0 (kernel resident resource manager)

        - Device /dev/tpm0 (hardware TPM)

        - TCP socket localhost:2321 (TPM simulator)

    Args:
        tcti Union[TCTI, str]: The TCTI context used to connect to the TPM (may be None). This
        is established using TCTILdr or a tpm2-tools style --tcti string in the format of
        <tcti-name>:<tcti-conf> where :<tcti-conf> is optional. Defaults to None.

    Returns:
        An instance of the ESAPI class.

    Raises:
        TypeError: If the TCTI is an invalid type.
        TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.
        RuntimeError: If a TCTI config string is not in name:conf or name format.

    This class implements the TCG defined Enhanced System API in Python see Notes below.

    Note that since this implementation is a binding, the underlying tss2-esys version will matter as far
    as the users mileage.

    Note that since the TCG has no specification on the ESAPI Python interface, liberties were taken to make
    use of features in Python not found in C. While the API is very similar to the C API, its not an exact
    match and, hopefully, will be simpler to use.

    The specification for the C library can be found at:
      - https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/

    C Function: Esys_Initialize
    """

    def __init__(self, tcti: Union[TCTI, str, None] = None):

        if not isinstance(tcti, (TCTI, type(None), str)):
            raise TypeError(
                f"Expected tcti to be type TCTI, str or None, got {type(tcti)}"
            )

        self._did_load_tcti = False

        # support tpm2-tools style tcti strings
        if isinstance(tcti, str):
            self._did_load_tcti = True
            tcti = TCTILdr.parse(tcti)

        self._tcti: Optional[TCTI] = tcti
        tctx = ffi.NULL if tcti is None else tcti._tcti_context

        self._ctx_pp = ffi.new("ESYS_CONTEXT **")
        _chkrc(lib.Esys_Initialize(self._ctx_pp, tctx, ffi.NULL))
        self._ctx = self._ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback) -> None:
        self.close()

    #
    # Close is used over tying this to the memory life cycle as __del__ means the GC has control
    # over when the underlying TCTI is free'd. Which could cause blocking from other ESAPI contexts
    # to the TPM.
    #
    def close(self) -> None:
        """Finalize an ESAPI Instance

        After interactions with the TPM the context holding the metadata needs to be
        freed. Since additional internal memory allocations may have happened during
        use of the context, it needs to be finalized correctly.

        C Function: Esys_Finalize
        """
        if self._ctx_pp:
            lib.Esys_Finalize(self._ctx_pp)
            self._ctx = ffi.NULL
            self._ctx_pp = ffi.NULL
        if self._did_load_tcti and self._tcti is not None:
            self._tcti.close()
        self._tcti = None

    def get_tcti(self) -> Optional[TCTI]:
        """Return the used TCTI context.

        If a TCTI was passed into Esys_Initialize then this tcti context is
        return. If None was passed in, then None will be returned.
        This function is useful before Esys_Finalize to retrieve the tcti context and
        perform a clean Tss2_Tcti_Finalize.

        Returns:
            A TCTI or None if None was passed to the ESAPI constructor.
        """
        return self._tcti

    @property
    def tcti(self) -> Optional[TCTI]:
        """Same as get_tcti()"""
        return self.get_tcti()

    def tr_from_tpmpublic(
        self,
        handle: TPM2_HANDLE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Creation of an ESYS_TR object from TPM metadata.

        This function can be used to create ESYS_TR object for Tpm Resources that are
        not created or loaded (e.g. using ESys_CreatePrimary or ESys_Load) but
        pre-exist inside the TPM. Examples are NV-Indices or persistent object.

        Since man in the middle attacks should be prevented as much as possible it is
        recommended to pass a session.

        Note: For PCRs and hierarchies, please use the global ESYS_TR identifiers.

        Note: If a session is provided the TPM is queried for the metadata twice.
        First without a session to retrieve some metadata then with the session where
        this metadata is used in the session HMAC calculation and thereby verified.

        Args:
            handle (TPM2_HANDLE): The handle of the TPM object to represent as ESYS_TR.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Returns:
            The newly created ESYS_TR metadata object.

        Raises:
            TypeError: If a type is not expected.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TR_FromTPMPublic
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        obj = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_TR_FromTPMPublic(
                self._ctx, handle, session1, session2, session3, obj,
            )
        )
        return ESYS_TR(obj[0])

    def tr_close(self, esys_handle: ESYS_TR) -> None:
        """Close an ESYS_TR without removing it from the TPM.

        This function deletes an ESYS_TR object from an ESYS_CONTEXT without deleting
        it from the TPM. This is useful for NV-Indices or persistent keys, after
        ESAPI.tr_serialize has been called. Transient objects should be deleted using
        ESAPI.flush_context.

        Args:
            esys_handle (ESYS_TR): The ESYS_TR metadata object to be deleted from ESAPI.

        Raises:
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TR_Close
        """

        _check_handle_type(esys_handle, "esys_handle")
        esys_tr_ptr = ffi.new("ESYS_TR *")
        esys_tr_ptr[0] = esys_handle
        _chkrc(lib.Esys_TR_Close(self._ctx, esys_tr_ptr))

    def tr_set_auth(
        self, esys_handle: ESYS_TR, auth_value: Union[TPM2B_AUTH, bytes, str, None]
    ) -> None:
        """Set the authorization value of an ESYS_TR.

        Authorization values are associated with ESYS_TR Tpm Resource object. They
        are then picked up whenever an authorization is needed.

        Note: The authorization value is not stored in the metadata during
        tr_serialize. Therefore tr_set_auth needs to be called again after
        every tr_deserialize.

        Args:
            esys_handle (ESYS_TR): The ESYS_TR for which to set the auth_value value.
            auth_value (Union[TPM2B_AUTH, bytes, str, None]): The auth_value value to set for the ESYS_TR or None to zero.
                Defaults to None.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TR_SetAuth
        """

        _check_handle_type(esys_handle, "esys_handle")

        if auth_value is None:
            auth_value = TPM2B_AUTH()

        auth_cdata = _get_cdata(auth_value, TPM2B_AUTH, "auth_value")
        _chkrc(lib.Esys_TR_SetAuth(self._ctx, esys_handle, auth_cdata))

    def tr_get_name(self, handle: ESYS_TR) -> TPM2B_NAME:
        """Retrieve the TPM public name of an Esys_TR object.

        Some operations (i.e. Esys_PolicyNameHash) require the name of a TPM object
        to be passed. Esys_TR_GetName provides this name to the caller.

        Args:
            handle (ESYS_TR): The ESYS_TR for which to get the name value.

        Returns:
            A TPM2B_NAME containing the name of the object referenced in the esys_handle.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TR_GetName
        """
        _check_handle_type(handle, "handle")

        name = ffi.new("TPM2B_NAME **")
        _chkrc(lib.Esys_TR_GetName(self._ctx, handle, name))
        return TPM2B_NAME(_cdata=_get_dptr(name, lib.Esys_Free))

    def startup(self, startup_type: TPM2_SU) -> None:
        """Invoke the TPM2_Startup command.

        This function invokes the TPM2_Startup command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            startup_type (TPM2_SU): TPM2_SU_CLEAR or TPM2_SU_STATE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_Startup

        TPM Command: TPM2_Startup
        """
        _check_friendly_int(startup_type, "startup_type", TPM2_SU)

        _chkrc(lib.Esys_Startup(self._ctx, startup_type))

    def shutdown(
        self,
        shutdown_type: TPM2_SU = TPM2_SU.STATE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_Shutdown command.

        This function invokes the TPM2_Shutdown command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            shutdown_type (TPM2_SU): TPM2_SU_CLEAR or TPM2_SU_STATE.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_Shutdown

        TPM Command: TPM2_Shutdown
        """

        _check_friendly_int(shutdown_type, "shutdown_type", TPM2_SU)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_Shutdown(self._ctx, session1, session2, session3, shutdown_type)
        )

    def self_test(
        self,
        full_test: bool,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_SelfTest command.

        This function invokes the TPM2_SelfTest command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            full_test (bool): True to run a full test. False to run tests that have yet to be executed.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_SelfTest

        TPM Command: TPM2_SelfTest
        """

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
        """Invoke the TPM2_IncrementalSelfTest command.

        This function invokes the TPM2_IncrementalSelfTest command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            to_test (TPML_ALG): List of algorithms that should be tested.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPML_ALG list of of algorithms that need testing; the todo list.

        C Function: Esys_IncrementalSelfTest

        TPM Command: TPM2_IncrementalSelfTest
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        to_test_cdata = _get_cdata(to_test, TPML_ALG, "to_test")

        todo_list = ffi.new("TPML_ALG **")
        _chkrc(
            lib.Esys_IncrementalSelfTest(
                self._ctx, session1, session2, session3, to_test_cdata, todo_list
            )
        )
        return TPML_ALG(_get_dptr(todo_list, lib.Esys_Free))

    def get_test_result(
        self,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_MAX_BUFFER, TPM2_RC]:
        """Invoke the TPM2_GetTestResult command.

        This function invokes the TPM2_GetTestResult command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_MAX_BUFFER, TPM2_RC] the test result data and the return code from the test execution.

        C Function: Esys_GetTestResult

        TPM Command: TPM2_GetTestResult
        """
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        out_data = ffi.new("TPM2B_MAX_BUFFER **")
        test_result = ffi.new("TPM2_RC *")
        _chkrc(
            lib.Esys_GetTestResult(
                self._ctx, session1, session2, session3, out_data, test_result
            )
        )
        return (
            TPM2B_MAX_BUFFER(_get_dptr(out_data, lib.Esys_Free)),
            TPM2_RC(test_result[0]),
        )

    def start_auth_session(
        self,
        tpm_key: ESYS_TR,
        bind: ESYS_TR,
        session_type: TPM2_SE,
        symmetric: TPMT_SYM_DEF,
        auth_hash: TPM2_ALG,
        nonce_caller: Union[TPM2B_NONCE, bytes, str, None] = None,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Invoke the TPM2_StartAuthSession command.

        This function invokes the TPM2_StartAuthSession command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            tpm_key (ESYS_TR): Handle of a loaded decrypt key used to encrypt salt.
            bind (ESYS_TR): Entity providing the authValue.
            session_type (TPM2_SE): Indicates the type of the session; simple HMAC or policy (including a trial policy).
            symmetric (TPMT_SYM_DEF): The algorithm and key size for parameter encryption.
            auth_hash (TPM2_ALG): Hash algorithm to use for the session.
            nonce_caller (Union[TPM2B_NONCE, bytes, str, None]): Initial nonceCaller, sets nonceTPM size for the
                session. Can be None to have ESAPI generate it for the caller. Defaults to None.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR which is the handle of the started session.

        C Function: Esys_StartAuthSession

        TPM Command: TPM2_StartAuthSession
        """

        _check_handle_type(tpm_key, "tpm_key")
        _check_handle_type(bind, "bind")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(session_type, "session_type", TPM2_SE)
        _check_friendly_int(auth_hash, "auth_hash", TPM2_ALG)

        nonce_caller_cdata = _get_cdata(
            nonce_caller, TPM2B_NONCE, "nonce_caller", allow_none=True
        )
        symmetric_cdata = _get_cdata(symmetric, TPMT_SYM_DEF, "symmetric")

        session_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_StartAuthSession(
                self._ctx,
                tpm_key,
                bind,
                session1,
                session2,
                session3,
                nonce_caller_cdata,
                session_type,
                symmetric_cdata,
                auth_hash,
                session_handle,
            )
        )

        return ESYS_TR(session_handle[0])

    def trsess_set_attributes(
        self, session: ESYS_TR, attributes: int, mask: int = 0xFF
    ) -> None:
        """Set session attributes.

        Set or unset a session's attributes according to the provided flags and mask.
        ``new_attributes = old_attributes & ~mask | flags & mask``
        Note: this function only applies to ESYS_TR objects that represent sessions.

        Args:
            session (ESYS_TR): The session handle.
            attributes (int): The attributes to be set or unset for the session.
            mask (int): The mask for the flags to be set or unset. Defaults to 0xFF.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TRSess_SetAttributes
        """
        _check_handle_type(session, "session")

        if not isinstance(attributes, int):
            raise TypeError(
                f"Expected attributes to be type int, got {type(attributes)}"
            )

        if not isinstance(mask, int):
            raise TypeError(f"Expected mask to be type int, got {type(attributes)}")

        _chkrc(lib.Esys_TRSess_SetAttributes(self._ctx, session, attributes, mask))

    def trsess_get_nonce_tpm(self, session: ESYS_TR) -> TPM2B_NONCE:
        """Retrieve the TPM nonce of an Esys_TR session object.

         Some operations (i.e. Esys_PolicySigned) require the nonce returned by the
         TPM during Esys_StartauthSession. This function provides this nonce to the
         caller.

        Args:
            session (ESYS_TR): The session handle.

        Returns:
            The TPMB_NONCE representing the current session nonce.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TRSess_GetNonceTPM
        """
        _check_handle_type(session, "session")

        nonce = ffi.new("TPM2B_NONCE **")

        _chkrc(lib.Esys_TRSess_GetNonceTPM(self._ctx, session, nonce))

        return TPM2B_NONCE(_get_dptr(nonce, lib.Esys_Free))

    def policy_restart(
        self,
        session_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_PolicyRestart command.

        This function invokes the TPM2_PolicyRestart command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            session_handle (ESYS_TR): The handle for the policy session.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyRestart

        TPM Command: TPM2_PolicyRestart
        """

        _check_handle_type(session_handle, "session_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyRestart(
                self._ctx, session_handle, session1, session2, session3
            )
        )

    def create(
        self,
        parent_handle: ESYS_TR,
        in_sensitive: Optional[TPM2B_SENSITIVE_CREATE],
        in_public: Union[TPM2B_PUBLIC, str] = "rsa2048",
        outside_info: Union[TPM2B_DATA, bytes, str] = TPM2B_DATA(),
        creation_pcr: Union[TPML_PCR_SELECTION, str] = TPML_PCR_SELECTION(),
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[
        TPM2B_PRIVATE, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION
    ]:
        """Invoke the TPM2_Create command.

        This function invokes the TPM2_Create command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            parent_handle (ESYS_TR): Handle of parent for new object.
            in_sensitive (TPM2B_SENSITIVE_CREATE): The sensitive data, can be None for an empty TPM2B_SENSITIVE_CREATE.
            in_public (Union[TPM2B_PUBLIC, str]): The public template. Defaults to an rsa2048 template.
            outside_info (Union[TPM2B_DATA, bytes, str]): Data that will be included in the creation data for
                this object to provide permanent, verifiable linkage between
                this object and some object owner data. Defaults to empty TPM2B_DATA.
            creation_pcr (Union[TPML_PCR_SELECTION, str]): PCR that will be used in creation data. Defaults to an empty PCR selection.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An Tuple[TPM2B_PRIVATE, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION].

        C Function: Esys_Create

        TPM Command: TPM2_Create
        """

        _check_handle_type(parent_handle, "parent_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_public_cdata = _get_cdata(in_public, TPM2B_PUBLIC, "in_public")

        if in_sensitive is None:
            in_sensitive = TPM2B_SENSITIVE_CREATE()
        in_sensitive_cdata = _get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        outside_info_cdata = _get_cdata(outside_info, TPM2B_DATA, "outside_info")
        creation_pCR_cdata = _get_cdata(
            creation_pcr, TPML_PCR_SELECTION, "creation_pcr"
        )

        out_private = ffi.new("TPM2B_PRIVATE **")
        out_public = ffi.new("TPM2B_PUBLIC **")
        creation_data = ffi.new("TPM2B_CREATION_DATA **")
        creation_hash = ffi.new("TPM2B_DIGEST **")
        creation_ticket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_Create(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                in_sensitive_cdata,
                in_public_cdata,
                outside_info_cdata,
                creation_pCR_cdata,
                out_private,
                out_public,
                creation_data,
                creation_hash,
                creation_ticket,
            )
        )
        return (
            TPM2B_PRIVATE(_get_dptr(out_private, lib.Esys_Free)),
            TPM2B_PUBLIC(_get_dptr(out_public, lib.Esys_Free)),
            TPM2B_CREATION_DATA(_get_dptr(creation_data, lib.Esys_Free)),
            TPM2B_DIGEST(_get_dptr(creation_hash, lib.Esys_Free)),
            TPMT_TK_CREATION(_get_dptr(creation_ticket, lib.Esys_Free)),
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
        """Invoke the TPM2_Load command.

        This function invokes the TPM2_Load command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            parent_handle (ESYS_TR): parentHandle TPM handle of parent key; shall not be a reserved
                handle.
            in_private (TPM2B_PRIVATE): The private portion of the object.
            in_public (TPM2B_PUBLIC): The public portion of the object.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR representing the handle of the loaded object.

        C Function: Esys_Load

        TPM Command: TPM2_Load
        """

        _check_handle_type(parent_handle, "parent_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_public_cdata = _get_cdata(in_public, TPM2B_PUBLIC, "in_public")
        in_private_cdata = _get_cdata(in_private, TPM2B_PRIVATE, "in_private")

        object_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_Load(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                in_private_cdata,
                in_public_cdata,
                object_handle,
            )
        )

        return ESYS_TR(object_handle[0])

    def load_external(
        self,
        in_public: TPM2B_PUBLIC,
        in_private: TPM2B_SENSITIVE = None,
        hierarchy: ESYS_TR = ESYS_TR.NULL,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Invoke the TPM2_LoadExternal command.

        This function invokes the TPM2_LoadExternal command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            in_public (TPM2B_PUBLIC): The public portion of the object.
            in_private (TPM2B_SENSITIVE): The sensitive portion of the object. Defaults to None.
            hierarchy (ESYS_TR): Hierarchy with which the object area is associated.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR representing the handle of the loaded object.

        C Function: Esys_LoadExternal

        TPM Command: TPM2_LoadExternal
        """

        _check_friendly_int(hierarchy, "hierarchy", ESYS_TR)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_private_cdata = _get_cdata(
            in_private, TPM2B_SENSITIVE, "in_private", allow_none=True
        )

        in_public_cdata = _get_cdata(in_public, TPM2B_PUBLIC, "in_public")

        hierarchy = ESAPI._fixup_hierarchy(hierarchy)

        object_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_LoadExternal(
                self._ctx,
                session1,
                session2,
                session3,
                in_private_cdata,
                in_public_cdata,
                hierarchy,
                object_handle,
            )
        )

        return ESYS_TR(object_handle[0])

    def read_public(
        self,
        object_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_PUBLIC, TPM2B_NAME, TPM2B_NAME]:
        """Invoke the TPM2_ReadPublic command.

        This function invokes the TPM2_ReadPublic command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            object_handle (ESYS_TR): Handle of the object.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_PUBLIC, TPM2B_NAME, TPM2B_NAME] which is the public portion of the object, the name
            and the qualified name respectively.

        C Function: Esys_ReadPublic

        TPM Command: TPM2_ReadPublic
        """

        _check_handle_type(object_handle, "object_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        out_public = ffi.new("TPM2B_PUBLIC **")
        name = ffi.new("TPM2B_NAME **")
        qualified_name = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_ReadPublic(
                self._ctx,
                object_handle,
                session1,
                session2,
                session3,
                out_public,
                name,
                qualified_name,
            )
        )
        return (
            TPM2B_PUBLIC(_get_dptr(out_public, lib.Esys_Free)),
            TPM2B_NAME(_get_dptr(name, lib.Esys_Free)),
            TPM2B_NAME(_get_dptr(qualified_name, lib.Esys_Free)),
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
        """Invoke the TPM2_ActivateCredential command.

        This function invokes the TPM2_ActivateCredential command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            activate_handle (ESYS_TR): Handle of the object associated with certificate
                in credentialBlob.
            key_handle (ESYS_TR): Loaded key used to decrypt the TPMS_SENSITIVE in
                credentialBlob.
            credential_blob (TPM2B_ID_OBJECT): The credential.
            secret (TPM2B_ENCRYPTED_SECRET): KeyHandle algorithm-dependent encrypted seed that
                protects credentialBlob.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            The cert_info, which is a TPM2B_DIGEST of the decrypted certificate information.

        C Function: Esys_ActivateCredential

        TPM Command: TPM2_ActivateCredential
        """
        _check_handle_type(activate_handle, "activate_handle")
        _check_handle_type(key_handle, "key_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        credential_blob_cdata = _get_cdata(
            credential_blob, TPM2B_ID_OBJECT, "credential_blob"
        )
        secret_cdata = _get_cdata(secret, TPM2B_ENCRYPTED_SECRET, "secret")

        cert_info = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_ActivateCredential(
                self._ctx,
                activate_handle,
                key_handle,
                session1,
                session2,
                session3,
                credential_blob_cdata,
                secret_cdata,
                cert_info,
            )
        )
        return TPM2B_DIGEST(_get_dptr(cert_info, lib.Esys_Free))

    def make_credential(
        self,
        handle: ESYS_TR,
        credential: TPM2B_DIGEST,
        object_name: TPM2B_NAME,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]:
        """Invoke the TPM2_MakeCredential command.

        This function invokes the TPM2_MakeCredential command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            handle (ESYS_TR): Loaded public area, used to encrypt the sensitive area
                containing the credential key.
            credential (TPM2B_DIGEST): The credential information.
            object_name (TPM2B_NAME): Name of the object to which the credential applies.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET] which is the credential_blob and the secret portions
            respectively. The secret is a handle algorithm-dependent data that wraps the key that encrypts
            credential_blob.

        C Function: Esys_MakeCredential

        TPM Command: TPM2_MakeCredential
        """

        _check_handle_type(handle, "handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        credential_cdata = _get_cdata(credential, TPM2B_DIGEST, "credential")
        object_name_cdata = _get_cdata(object_name, TPM2B_NAME, "object_name")

        credential_blob = ffi.new("TPM2B_ID_OBJECT **")
        secret = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_MakeCredential(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                credential_cdata,
                object_name_cdata,
                credential_blob,
                secret,
            )
        )
        return (
            TPM2B_ID_OBJECT(_get_dptr(credential_blob, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(_get_dptr(secret, lib.Esys_Free)),
        )

    def unseal(
        self,
        item_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_SENSITIVE_DATA:
        """Invoke the TPM2_Unseal command.

        This function invokes the TPM2_Unseal command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            item_handle (ESYS_TR): The handle of a loaded data object.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_SENSITIVE_DATA which is the unsealed data.

        C Function: Esys_Unseal

        TPM Command: TPM2_Unseal
        """
        _check_handle_type(item_handle, "item_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        out_data = ffi.new("TPM2B_SENSITIVE_DATA **")
        _chkrc(
            lib.Esys_Unseal(
                self._ctx, item_handle, session1, session2, session3, out_data
            )
        )
        return TPM2B_SENSITIVE_DATA(_get_dptr(out_data, lib.Esys_Free))

    def object_change_auth(
        self,
        object_handle: ESYS_TR,
        parent_handle: ESYS_TR,
        new_auth: Union[TPM2B_AUTH, str, bytes],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PRIVATE:
        """Invoke the TPM2_ObjectChangeAuth command.

        This function invokes the TPM2_ObjectChangeAuth command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            object_handle (ESYS_TR): Handle of the object.
            parent_handle (ESYS_TR): Handle of the parent.
            new_auth (Union[TPM2B_AUTH, str, bytes]): New authorization value.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A new TPM2B_PRIVATE which includes the new_auth value.

        C Function: Esys_ObjectChangeAuth

        TPM Command: TPM2_ObjectChangeAuth
        """
        _check_handle_type(object_handle, "object_handle")
        _check_handle_type(parent_handle, "parent_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        new_auth_cdata = _get_cdata(new_auth, TPM2B_AUTH, "new_auth")

        out_private = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_ObjectChangeAuth(
                self._ctx,
                object_handle,
                parent_handle,
                session1,
                session2,
                session3,
                new_auth_cdata,
                out_private,
            )
        )
        return TPM2B_PRIVATE(_get_dptr(out_private, lib.Esys_Free))

    def create_loaded(
        self,
        parent_handle: ESYS_TR,
        in_sensitive: Optional[TPM2B_SENSITIVE_CREATE],
        in_public: Union[TPM2B_TEMPLATE, str] = "rsa2048",
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[ESYS_TR, TPM2B_PRIVATE, TPM2B_PUBLIC]:
        """Invoke the TPM2_CreateLoaded command.

        This function invokes the TPM2_CreateLoaded command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            parent_handle (ESYS_TR): TPM2_Handle of a transient storage key, a persistent
                storage key, ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER, ESYS_TR.PLATFORM+{PP},
                or ESYS_TR.NULL.
            in_sensitive (TPM2B_SENSITIVE_CREATE): The sensitive data, see TPM 2.0 Part 1 Sensitive
                Values. Accepts None for an empty TPM2B_SENSITIVE_CREATE.
            in_public (Union[TPM2B_TEMPLATE, str]): The public template (optional). Defaults to an rsa2048 key.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[ESYS_TR, TPM2B_PRIVATE, TPM2B_PUBLIC] which is the handle of the loaded object(object_handle),
            the sensitive area of the object (out_private), and the public portion of the created object (out_public).

        C Function: Esys_CreateLoaded

        TPM Command: TPM2_CreateLoaded
        """
        _check_handle_type(parent_handle, "parent_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        if isinstance(in_public, str):
            in_public = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(in_public).marshal())

        if in_sensitive is None:
            in_sensitive = TPM2B_SENSITIVE_CREATE()
        in_sensitive_cdata = _get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        in_public_cdata = _get_cdata(in_public, TPM2B_TEMPLATE, "in_public")

        object_handle = ffi.new("ESYS_TR *")
        out_private = ffi.new("TPM2B_PRIVATE **")
        out_public = ffi.new("TPM2B_PUBLIC **")
        _chkrc(
            lib.Esys_CreateLoaded(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                in_sensitive_cdata,
                in_public_cdata,
                object_handle,
                out_private,
                out_public,
            )
        )

        return (
            ESYS_TR(object_handle[0]),
            TPM2B_PRIVATE(_get_dptr(out_private, lib.Esys_Free)),
            TPM2B_PUBLIC(_get_dptr(out_public, lib.Esys_Free)),
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
        """Invoke the TPM2_Duplicate command.

        This function invokes the TPM2_Duplicate command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            object_handle (ESYS_TR): Loaded object to duplicate.
            new_parent_handle (ESYS_TR): The duplication parent, and hall reference the public area of an asymmetric
                 key.
            encryption_key_in (TPM2B_DATA): Symmetric encryption key. Can be None if no wrapping is to be performed.
            symmetric_alg (TPMT_SYM_DEF_OBJECT): Definition for the symmetric algorithm to be used
                for the inner wrapper
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET] which is the
            TPM2_If the caller provided an encryption key or if symmetric_alg was
            TPM2_ALG.NULL, then this will be the TPM2_Empty TPM2_Buffer; otherwise,
            it shall contain the TPM2_TPM-generated, symmetric encryption key for the
            inner wrapper, duplicate Private area that may be encrypted by encryption_key_in;
            and may be doubly encrypted and the Seed protected by the asymmetric algorithms
            of new parent (NP).

        C Function: Esys_Duplicate

        TPM Command: TPM2_Duplicate
        """
        _check_handle_type(object_handle, "object_handle")
        _check_handle_type(new_parent_handle, "new_parent_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        encryption_key_in_cdata = _get_cdata(
            encryption_key_in, TPM2B_DATA, "encryption_key_in", allow_none=True
        )
        symmetric_alg_cdata = _get_cdata(
            symmetric_alg, TPMT_SYM_DEF_OBJECT, "symmetric_alg"
        )

        encryption_key_out = ffi.new("TPM2B_DATA **")
        duplicate = ffi.new("TPM2B_PRIVATE **")
        out_sym_seed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Duplicate(
                self._ctx,
                object_handle,
                new_parent_handle,
                session1,
                session2,
                session3,
                encryption_key_in_cdata,
                symmetric_alg_cdata,
                encryption_key_out,
                duplicate,
                out_sym_seed,
            )
        )

        return (
            TPM2B_DATA(_get_dptr(encryption_key_out, lib.Esys_Free)),
            TPM2B_PRIVATE(_get_dptr(duplicate, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(_get_dptr(out_sym_seed, lib.Esys_Free)),
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
        """Invoke the TPM2_Rewrap command.

        This function invokes the TPM2_Rewrap command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            old_parent (ESYS_TR): Parent of object.
            new_parent (ESYS_TR): New parent of the object.
            in_duplicate (TPM2B_PRIVATE): An object encrypted using symmetric key derived from
                inSymSeed.
            name (Union[TPM2B_NAME, bytes, str]): The Name of the object being rewrapped.
            in_sym_seed (TPM2B_ENCRYPTED_SECRET): The seed for the symmetric key and HMAC key.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET] which is the object encrypted using
            symmetric key derived from out_sym_seed and out_sym_seed which is the Seed for a
            symmetric key protected by newParent asymmetric key respecitevely.

        C Function: Esys_Rewrap

        TPM Command: TPM2_Rewrap
        """
        _check_handle_type(old_parent, "old_parent")
        _check_handle_type(new_parent, "new_parent")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_duplicate_cdata = _get_cdata(in_duplicate, TPM2B_PRIVATE, "in_duplicate")

        in_sym_seed_cdata = _get_cdata(
            in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed"
        )

        name_cdata = _get_cdata(name, TPM2B_NAME, "name")

        out_duplicate = ffi.new("TPM2B_PRIVATE **")
        out_sym_seed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Rewrap(
                self._ctx,
                old_parent,
                new_parent,
                session1,
                session2,
                session3,
                in_duplicate_cdata,
                name_cdata,
                in_sym_seed_cdata,
                out_duplicate,
                out_sym_seed,
            )
        )
        return (
            TPM2B_PRIVATE(_get_dptr(out_duplicate, lib.Esys_Free)),
            TPM2B_ENCRYPTED_SECRET(_get_dptr(out_sym_seed, lib.Esys_Free)),
        )

    def import_(
        self,
        parent_handle: ESYS_TR,
        encryption_key: Union[TPM2B_DATA, bytes, str],
        object_public: TPM2B_PUBLIC,
        duplicate: TPM2B_PRIVATE,
        in_sym_seed: TPM2B_ENCRYPTED_SECRET,
        symmetric_alg: TPMT_SYM_DEF_OBJECT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_PRIVATE:
        """Invoke the TPM2_Import command.

        This function invokes the TPM2_Import command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            parent_handle (ESYS_TR): The handle of the new parent for the object.
            encryption_key (Union[TPM2B_DATA, bytes, str]): The optional symmetric
                encryption key used as the inner wrapper for duplicate.
            object_public (TPM2B_PUBLIC): The public area of the object to be imported.
            duplicate (TPM2B_PRIVATE): The symmetrically encrypted duplicate object that may
                contain an inner symmetric wrapper.
            in_sym_seed (TPM2B_ENCRYPTED_SECRET): The seed for the symmetric key and HMAC key.
            symmetric_alg (TPMT_SYM_DEF_OBJECT): Definition for the symmetric algorithm to use for
                the inner wrapper.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_PRIVATE which is the sensitive area encrypted with the symmetric key
            of parentHandle.

        C Function: Esys_Import

        TPM Command: TPM2_Import
        """
        _check_handle_type(parent_handle, "parent_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        encryption_key_cdata = _get_cdata(encryption_key, TPM2B_DATA, "encryption_key")

        object_public_cdata = _get_cdata(object_public, TPM2B_PUBLIC, "object_public")

        duplicate_cdata = _get_cdata(duplicate, TPM2B_PRIVATE, "duplicate")

        in_sym_seed_cdata = _get_cdata(
            in_sym_seed, TPM2B_ENCRYPTED_SECRET, "in_sym_seed"
        )

        symmetric_alg_cdata = _get_cdata(
            symmetric_alg, TPMT_SYM_DEF_OBJECT, "symmetric_alg"
        )

        out_private = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_Import(
                self._ctx,
                parent_handle,
                session1,
                session2,
                session3,
                encryption_key_cdata,
                object_public_cdata,
                duplicate_cdata,
                in_sym_seed_cdata,
                symmetric_alg_cdata,
                out_private,
            )
        )
        return TPM2B_PRIVATE(_get_dptr(out_private, lib.Esys_Free))

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
        """Invoke the TPM2_RSA_Encrypt command.

        This function invokes the TPM2_RSA_Encrypt command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): Reference to public portion of RSA key to use for
                encryption.
            message (Union[TPM2B_PUBLIC_KEY_RSA, bytes, str]): Message to be encrypted.
            in_scheme (TPMT_RSA_DECRYPT): TPM2_The padding scheme to use if scheme associated with
                keyHandle is TPM2_ALG_NULL.
            label (Union[TPM2B_DATA, bytes, str, None]): label to be associated with the message (optional).
                Defaults to None.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_PUBLIC_KEY_RSA which is the encrypted output.

        C Function: Esys_RSA_Encrypt

        TPM Command: TPM2_RSA_Encrypt
        """

        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        message_cdata = _get_cdata(message, TPM2B_PUBLIC_KEY_RSA, "message")
        label_cdata = _get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        out_data = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Encrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                message_cdata,
                in_scheme_cdata,
                label_cdata,
                out_data,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(_get_dptr(out_data, lib.Esys_Free))

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
        """Invoke the TPM2_RSA_Decrypt command.

        This function invokes the TPM2_RSA_Decrypt command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): RSA key to use for decryption.
            cipher_text (Union[TPM2B_PUBLIC_KEY_RSA, bytes, str]): Cipher text to be decrypted.
            in_scheme (TPMT_RSA_DECRYPT): TPM2_The padding scheme to use if scheme associated with
                keyHandle is TPM2_ALG_NULL.
            label (Union[TPM2B_DATA, bytes, str, None]): whose association with the message is to be verified.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_PUBLIC_KEY_RSA which is the Decrypted output.

        C Function: Esys_RSA_Decrypt

        TPM Command: TPM2_RSA_Decrypt
        """

        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_RSA_DECRYPT, "in_scheme")
        cipher_text_cdata = _get_cdata(cipher_text, TPM2B_PUBLIC_KEY_RSA, "cipher_text")
        label_cdata = _get_cdata(label, TPM2B_DATA, "label", allow_none=True)

        message = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Decrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                cipher_text_cdata,
                in_scheme_cdata,
                label_cdata,
                message,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(_get_dptr(message, lib.Esys_Free))

    def ecdh_key_gen(
        self,
        key_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT]:
        """Invoke the TPM2_ECDH_KeyGen command.

        This function invokes the TPM2_ECDH_KeyGen command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): Handle of a loaded ECC key public area.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT] which is the zPoint Results of P := h[de]Qs
            and pubPoint Generated ephemeral public point (Qe) respectively.

        C Function: Esys_ECDH_KeyGen

        TPM Command: TPM2_ECDH_KeyGen
        """

        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        z_point = ffi.new("TPM2B_ECC_POINT **")
        pub_point = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_KeyGen(
                self._ctx, key_handle, session1, session2, session3, z_point, pub_point
            )
        )
        return (
            TPM2B_ECC_POINT(_get_dptr(z_point, lib.Esys_Free)),
            TPM2B_ECC_POINT(_get_dptr(pub_point, lib.Esys_Free)),
        )

    def ecdh_zgen(
        self,
        key_handle: ESYS_TR,
        in_point: TPM2B_ECC_POINT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_ECC_POINT:
        """Invoke the TPM2_ECDH_ZGen command.

        This function invokes the TPM2_ECDH_ZGen command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): Handle of a loaded ECC key.
            in_point (TPM2B_ECC_POINT): A public key.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_ECC_POINT which is the X and Y coordinates of the product of the
                multiplication Z = (xZ , yZ) := [hdS]QB.

        C Function: Esys_ECDH_ZGen

        TPM Command: TPM2_ECDH_ZGen
        """

        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_point_cdata = _get_cdata(in_point, TPM2B_ECC_POINT, "in_point")

        out_point = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_ZGen(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                in_point_cdata,
                out_point,
            )
        )
        return TPM2B_ECC_POINT(_get_dptr(out_point, lib.Esys_Free))

    def ecc_parameters(
        self,
        curve_id: TPM2_ECC_CURVE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMS_ALGORITHM_DETAIL_ECC:
        """Invoke the TPM2_ECC_Parameters command.

        This function invokes the TPM2_ECC_Parameters command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            curve_id (TPM2_ECC_CURVE): Parameter set selector.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPMS_ALGORITHM_DETAIL_ECC ECC parameters for the selected curve.

        C Function: Esys_ECC_Parameters

        TPM Command: TPM2_ECC_Parameters
        """

        _check_friendly_int(curve_id, "curve_id", TPM2_ECC_CURVE)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        parameters = ffi.new("TPMS_ALGORITHM_DETAIL_ECC **")
        _chkrc(
            lib.Esys_ECC_Parameters(
                self._ctx, session1, session2, session3, curve_id, parameters
            )
        )
        return TPMS_ALGORITHM_DETAIL_ECC(_get_dptr(parameters, lib.Esys_Free))

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
    ) -> Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT]:
        """Invoke the TPM2_ZGen_2Phase command.

        This function invokes the TPM2_ZGen_2Phase command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_a (ESYS_TR): Handle of an unrestricted decryption key ECC.
            in_qs_b (TPM2B_ECC_POINT): party's static public key (Qs,B = (Xs,B, Ys,B)).
            in_qe_b (TPM2B_ECC_POINT): party's ephemeral public key (Qe,B = (Xe,B, Ye,B)).
            in_scheme (TPM2_ALG): The key exchange scheme.
            counter (int): Value returned by TPM2_EC_Ephemeral().
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT] which are the X and Y coordinates of the first and second
            computed values (scheme dependent) respectively.

        C Function: Esys_ZGen_2Phase

        TPM Command: TPM2_ZGen_2Phase
        """

        _check_handle_type(session1, "key_a")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(in_scheme, "in_scheme", TPM2_ALG)

        if not isinstance(counter, int):
            raise TypeError(f"Expected counter to be type int, got {type(counter)}")

        if counter < 0 or counter > 65535:
            raise ValueError(
                f"Expected counter to be in range of uint16_t, got {counter}"
            )

        in_qs_b_cdata = _get_cdata(in_qs_b, TPM2B_ECC_POINT, "in_qs_b")
        in_qe_b_cdata = _get_cdata(in_qe_b, TPM2B_ECC_POINT, "in_qe_b")

        out_z1 = ffi.new("TPM2B_ECC_POINT **")
        out_z2 = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ZGen_2Phase(
                self._ctx,
                key_a,
                session1,
                session2,
                session3,
                in_qs_b_cdata,
                in_qe_b_cdata,
                in_scheme,
                counter,
                out_z1,
                out_z2,
            )
        )

        return (
            TPM2B_ECC_POINT(_get_dptr(out_z1, lib.Esys_Free)),
            TPM2B_ECC_POINT(_get_dptr(out_z2, lib.Esys_Free)),
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
        """Invoke the TPM2_EncryptDecrypt command.

        This function invokes the TPM2_EncryptDecrypt command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): The symmetric key used for the operation.
            decrypt (bool): If True, then the operation is decryption; if False, the
                operation is encryption.
            mode (TPM2_ALG): Symmetric mode.
            iv_in (Union[TPM2B_IV, bytes, str]): An initial value as required by the algorithm.
            in_data (Union[TPM2B_MAX_BUFFER, bytes, str]): The data to be encrypted/decrypted.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_MAX_BUFFER, TPM2B_IV] which is the encrypted or decrypted output and the
            chaining value to use for IV in next round respectively.

        C Function: Esys_EncryptDecrypt

        TPM Command: TPM2_EncryptDecrypt
        """

        _check_handle_type(key_handle, "key_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(mode, "mode", TPM2_ALG)

        iv_in_cdata = _get_cdata(iv_in, TPM2B_IV, "iv_in")
        in_data_cdata = _get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError(f"Expected decrypt to be type bool, got {type(decrypt)}")

        out_data = ffi.new("TPM2B_MAX_BUFFER **")
        iv_out = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                decrypt,
                mode,
                iv_in_cdata,
                in_data_cdata,
                out_data,
                iv_out,
            )
        )
        return (
            TPM2B_MAX_BUFFER(_get_dptr(out_data, lib.Esys_Free)),
            TPM2B_IV(_get_dptr(iv_out, lib.Esys_Free)),
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
        """Invoke the TPM2_EncryptDecrypt2 command.

        This function invokes the TPM2_EncryptDecrypt2 command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): The symmetric key used for the operation.
            decrypt (bool): If True, then the operation is decryption; if False, the
                operation is encryption.
            mode (TPM2_ALG): Symmetric mode.
            iv_in (Union[TPM2B_IV, bytes, str]): An initial value as required by the algorithm.
            in_data (Union[TPM2B_MAX_BUFFER, bytes, str]): The data to be encrypted/decrypted.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_MAX_BUFFER, TPM2B_IV] which is the encrypted or decrypted output and the
            chaining value to use for IV in next round respectively.

        C Function: Esys_EncryptDecrypt2

        TPM Command: TPM2_EncryptDecrypt2
        """

        _check_handle_type(key_handle, "key_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(mode, "mode", TPM2_ALG)

        iv_in_cdata = _get_cdata(iv_in, TPM2B_IV, "iv_in")
        in_data_cdata = _get_cdata(in_data, TPM2B_MAX_BUFFER, "in_data")

        if not isinstance(decrypt, bool):
            raise TypeError("Expected decrypt to be type bool, got {type(decrypt)}")

        out_data = ffi.new("TPM2B_MAX_BUFFER **")
        iv_out = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt2(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                in_data_cdata,
                decrypt,
                mode,
                iv_in_cdata,
                out_data,
                iv_out,
            )
        )
        return (
            TPM2B_MAX_BUFFER(_get_dptr(out_data, lib.Esys_Free)),
            TPM2B_IV(_get_dptr(iv_out, lib.Esys_Free)),
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
        """Invoke the TPM2_Hash command.

        This function invokes the TPM2_Hash command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            data (Union[TPM2B_MAX_BUFFER, bytes, str]): Data to be hashed.
            hash_alg (TPM2_ALG): TPM2_Algorithm for the hash being computed - shall not be TPM2_ALG_NULL.
            hierarchy (ESYS_TR): Hierarchy to use for the ticket (ESYS_TR.NULL allowed). Defaults to ESYS_TR.OWNER.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK] which is the hash and validation TPM2_Ticket indicating that the sequence of octets used to
            compute outDigest did not start with TPM2_GENERATED_VALUE respectively.

        C Function: Esys_Hash

        TPM Command: TPM2_Hash
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        _check_friendly_int(hierarchy, "hierarchy", ESYS_TR)
        hierarchy = ESAPI._fixup_hierarchy(hierarchy)

        data_cdata = _get_cdata(data, TPM2B_MAX_BUFFER, "data")

        out_hash = ffi.new("TPM2B_DIGEST **")
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
                out_hash,
                validation,
            )
        )
        return (
            TPM2B_DIGEST(_get_dptr(out_hash, lib.Esys_Free)),
            TPMT_TK_HASHCHECK(_get_dptr(validation, lib.Esys_Free)),
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
        """Invoke the TPM2_HMAC command.

        This function invokes the TPM2_HMAC command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            handle (ESYS_TR): Handle for the symmetric signing key providing the HMAC key.
            buffer (Union[TPM2B_MAX_BUFFER, bytes, str]): HMAC data.
            hash_alg (TPM2_ALG): Algorithm to use for HMAC.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_DIGEST result of the HMAC.

        C Function: Esys_HMAC

        TPM Command: TPM2_HMAC
        """
        _check_handle_type(handle, "handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        buffer_cdata = _get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer")

        out_hMAC = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_HMAC(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                buffer_cdata,
                hash_alg,
                out_hMAC,
            )
        )
        return TPM2B_DIGEST(_get_dptr(out_hMAC, lib.Esys_Free))

    def get_random(
        self,
        bytes_requested: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DIGEST:
        """Invoke the TPM2_GetRandom command.

        This function invokes the TPM2_GetRandom command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            bytes_requested (int): Number of octets to return.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_DIGEST of the random octets.

        C Function: Esys_GetRandom

        TPM Command: TPM2_GetRandom
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        if not isinstance(bytes_requested, int):
            raise TypeError(
                f"Expected bytes_requested type to be int, got {type(bytes_requested)}"
            )

        random_bytes = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_GetRandom(
                self._ctx, session1, session2, session3, bytes_requested, random_bytes
            )
        )

        return TPM2B_DIGEST(_get_dptr(random_bytes, lib.Esys_Free))

    def stir_random(
        self,
        in_data: Union[TPM2B_SENSITIVE_DATA, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_StirRandom command.

        This function invokes the TPM2_StirRandom command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            in_data (Union[TPM2B_SENSITIVE_DATA, bytes, str]): Additional information.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_StirRandom

        TPM Command: TPM2_StirRandom
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_data_cdata = _get_cdata(in_data, TPM2B_SENSITIVE_DATA, "in_data")

        _chkrc(
            lib.Esys_StirRandom(self._ctx, session1, session2, session3, in_data_cdata)
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
        """Invoke the TPM2_HMAC_Start command.

        This function invokes the TPM2_HMAC_Start command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            handle (ESYS_TR): Handle of an HMAC key.
            auth (Union[TPM2B_AUTH, bytes, str]): Authorization value for subsequent use of the sequence.
            hash_alg (TPM2_ALG): The hash algorithm to use for the HMAC.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR handle of ESYS resource for TPMI_DH_OBJECT.

        C Function: Esys_HMAC_Start

        TPM Command: TPM2_HMAC_Start
        """

        _check_handle_type(handle, "handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = _get_cdata(auth, TPM2B_AUTH, "auth")

        sequence_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HMAC_Start(
                self._ctx,
                handle,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequence_handle,
            )
        )

        return ESYS_TR(sequence_handle[0])

    def hash_sequence_start(
        self,
        auth: Union[TPM2B_AUTH, bytes, str],
        hash_alg: TPM2_ALG,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Invoke the TPM2_HashSequenceStart command.

        This function invokes the TPM2_HashSequenceStart command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth (Union[TPM2B_AUTH, bytes, str]): Authorization value for subsequent use of the sequence.
            hash_alg (TPM2_ALG): The hash algorithm to use for the hash sequence.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR handle of ESYS resource for TPMI_DH_OBJECT.

        C Function: Esys_HashSequenceStart

        TPM Command: TPM2_HashSequenceStart
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        if auth is None:
            auth = TPM2B_AUTH()

        auth_cdata = _get_cdata(auth, TPM2B_AUTH, "auth")

        sequence_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HashSequenceStart(
                self._ctx,
                session1,
                session2,
                session3,
                auth_cdata,
                hash_alg,
                sequence_handle,
            )
        )

        return ESYS_TR(sequence_handle[0])

    def sequence_update(
        self,
        sequence_handle: ESYS_TR,
        buffer: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_SequenceUpdate command.

        This function invokes the TPM2_SequenceUpdate command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sequence_handle (ESYS_TR): Handle for the sequence object.
            buffer (Union[TPM2B_MAX_BUFFER, bytes, str]): Data to be added to hash.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_SequenceUpdate

        TPM Command: TPM2_SequenceUpdate
        """

        _check_handle_type(sequence_handle, "sequence_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        buffer_cdata = _get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

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
        """Invoke the TPM2_SequenceComplete command.

        This function invokes the TPM2_SequenceComplete command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sequence_handle (ESYS_TR): Authorization for the sequence.
            buffer (Union[TPM2B_MAX_BUFFER, bytes, str]): Data to be added to the hash/HMAC.
            hierarchy (ESYS_TR): Hierarchy of the ticket for a hash.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_DIGEST, TPMT_TK_HASHCHECK] which is the The returned HMAC or digest in a sized buffer
            and the TPM2_Ticket indicating that the sequence of octets used to compute outDigest did not start
            with TPM2_GENERATED_VALUE respectively.

        C Function: Esys_SequenceComplete

        TPM Command: TPM2_SequenceComplete
        """

        _check_handle_type(sequence_handle, "sequence_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(hierarchy, "hierarchy", ESYS_TR)
        hierarchy = ESAPI._fixup_hierarchy(hierarchy)

        buffer_cdata = _get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

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
            TPM2B_DIGEST(_get_dptr(result, lib.Esys_Free)),
            TPMT_TK_HASHCHECK(_get_dptr(validation, lib.Esys_Free)),
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
        """Invoke the TPM2_EventSequenceComplete command.

        This function invokes the TPM2_EventSequenceComplete command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_handle (ESYS_TR): PCR to be extended with the Event data.
            sequence_handle (ESYS_TR): Authorization for the sequence.
            buffer (Union[TPM2B_MAX_BUFFER, bytes, str]): Data to be added to the Event.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPML_DIGEST_VALUES a list of digests computed for the PCR.

        C Function: Esys_EventSequenceComplete

        TPM Command: TPM2_EventSequenceComplete
        """

        _check_handle_type(sequence_handle, "sequence_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        buffer_cdata = _get_cdata(buffer, TPM2B_MAX_BUFFER, "buffer", allow_none=True)

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
        return TPML_DIGEST_VALUES(_get_dptr(results, lib.Esys_Free))

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
        """Invoke the TPM2_Certify command.

        This function invokes the TPM2_Certify command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            object_handle (ESYS_TR): Handle of the object to be certified.
            sign_handle (ESYS_TR): Handle of the key used to sign the attestation    structure.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): User provided qualifying data.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG_NULL.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the structure that was signed, known as certify_info and
            the signature computed over certify_info.

        C Function: Esys_Certify

        TPM Command: TPM2_Certify
        """

        _check_handle_type(object_handle, "object_handle")
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data"
        )
        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        certify_info = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Certify(
                self._ctx,
                object_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifying_data_cdata,
                in_scheme_cdata,
                certify_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(certify_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
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
        """Invoke the TPM2_CertifyCreation command.

        This function invokes the TPM2_CertifyCreation command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the key that will sign the attestation block.
            object_handle (ESYS_TR): The object associated with the creation data.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): User provided qualifying data.
            creation_hash (Union[TPM2B_DIGEST, bytes, str]): Hash of the creation data produced by TPM2_Create()
                or TPM2_CreatePrimary().
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG_NULL.
            creation_ticket (TPMT_TK_CREATION): Ticket produced by TPM2_Create() or TPM2_CreatePrimary().
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the structure that was signed, known as certify_info and
            the signature computed over certify_info.

        C Function: Esys_CertifyCreation

        TPM Command: TPM2_CertifyCreation
        """

        _check_handle_type(object_handle, "object_handle")
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data"
        )
        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        creation_hash_cdata = _get_cdata(creation_hash, TPM2B_DIGEST, "creation_hash")
        creation_ticket_cdata = _get_cdata(
            creation_ticket, TPMT_TK_CREATION, "creation_ticket"
        )

        certify_info = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_CertifyCreation(
                self._ctx,
                sign_handle,
                object_handle,
                session1,
                session2,
                session3,
                qualifying_data_cdata,
                creation_hash_cdata,
                in_scheme_cdata,
                creation_ticket_cdata,
                certify_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(certify_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
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
        """Invoke the TPM2_Quote command.

        This function invokes the TPM2_Quote command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of key that will perform signature.
            pcr_select (Union[TPML_PCR_SELECTION, str]): PCR set to quote.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): Data supplied by the caller.
            in_scheme (TPMT_SIG_SCHEME):  TPM2_Signing scheme to use if the scheme for signHandle is TPM2_ALG_NULL (optional).
                Defaults to TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL).
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the quoted information, known as quoted and
            the signature over quoted.

        C Function: Esys_Quote

        TPM Command: TPM2_Quote
        """

        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data"
        )

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        PCRselect_cdata = _get_cdata(pcr_select, TPML_PCR_SELECTION, "pcr_select")

        quoted = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Quote(
                self._ctx,
                sign_handle,
                session1,
                session2,
                session3,
                qualifying_data_cdata,
                in_scheme_cdata,
                PCRselect_cdata,
                quoted,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(quoted, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
        )

    def get_session_audit_digest(
        self,
        sign_handle: ESYS_TR,
        session_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle: ESYS_TR = ESYS_TR.ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:
        """Invoke the TPM2_GetSessionAuditDigest command.

        This function invokes the TPM2_GetSessionAuditDigest command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the signing key.
            session_handle (ESYS_TR): Handle of the audit session.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): User-provided qualifying data - may be
                zero-length.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG_NULL (optional). Defaults to TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL).
            privacy_admin_handle (ESYS_TR): TPM2_Handle of the privacy administrator must be ESYS_TR.ENDORSEMENT.
                Defaults to ESYS_TR.ENDORSEMENT (optional).
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the audit information that was signed, known as audit_info,
            and the signature over audit_info.

        C Function: Esys_GetSessionAuditDigest

        TPM Command: TPM2_GetSessionAuditDigest
        """

        _check_handle_type(session_handle, "session_handle")
        _check_handle_type(
            privacy_admin_handle,
            "privacy_admin_handle",
            expected=[ESYS_TR.ENDORSEMENT],
        )
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        audit_info = ffi.new("TPM2B_ATTEST **")
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
                qualifying_data_cdata,
                in_scheme_cdata,
                audit_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(audit_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
        )

    def get_command_audit_digest(
        self,
        sign_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_handle: ESYS_TR = ESYS_TR.ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:
        """Invoke the TPM2_GetCommandAuditDigest command.

        This function invokes the TPM2_GetCommandAuditDigest command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the signing key.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): Other data to associate with this audit digest.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG_NULL (optional). Defaults to TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL).
            privacy_handle (ESYS_TR): TPM2_Handle of the privacy administrator must be ESYS_TR.ENDORSEMENT.
                Defaults to ESYS_TR.ENDORSEMENT (optional).
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the audit information that was signed, known as audit_info,
            and the signature over audit_info.

        C Function: Esys_GetCommandAuditDigest

        TPM Command: TPM2_GetCommandAuditDigest
        """

        _check_handle_type(
            privacy_handle, "privacy_handle", expected=[ESYS_TR.ENDORSEMENT]
        )
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        audit_info = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetCommandAuditDigest(
                self._ctx,
                privacy_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifying_data_cdata,
                in_scheme_cdata,
                audit_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(audit_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
        )

    def get_time(
        self,
        sign_handle: ESYS_TR,
        qualifying_data: Union[TPM2B_DATA, bytes, str],
        in_scheme: TPMT_SIG_SCHEME = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        privacy_admin_handle: ESYS_TR = ESYS_TR.ENDORSEMENT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:
        """Invoke the TPM2_GetTime command.

        This function invokes the TPM2_GetTime command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the signing key.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): Other data to associate with this audit digest.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG_NULL (optional). Defaults to TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL).
            privacy_admin_handle (ESYS_TR): TPM2_Handle of the privacy administrator must be ESYS_TR.ENDORSEMENT.
                Defaults to ESYS_TR.ENDORSEMENT (optional).
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] Standard TPM-generated attestation block, known as time_info, and
            the signature over time_info respectively.

        C Function: Esys_GetTime

        TPM Command: TPM2_GetTime
        """

        _check_handle_type(
            privacy_admin_handle, "privacy_admin_handle", expected=[ESYS_TR.ENDORSEMENT]
        )
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data", allow_none=True
        )

        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        time_info = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetTime(
                self._ctx,
                privacy_admin_handle,
                sign_handle,
                session1,
                session2,
                session3,
                qualifying_data_cdata,
                in_scheme_cdata,
                time_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(time_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
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
        """Invoke the TPM2_Commit command.

        This function invokes the TPM2_Commit command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the key that will be used in the signing
                operation
            p1 (TPM2B_ECC_POINT): A point (M) on the curve used by signHandle.
            s2 (Union[TPM2B_SENSITIVE_DATA, bytes, str]): Octet array used to derive x-coordinate of a base point.
            y2 (Union[TPM2B_ECC_PARAMETER, bytes, str]): Y coordinate of the point associated with s2.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ECC_POINT, TPM2B_ECC_POINT, TPM2B_ECC_POINT, int] which is the K point as
            ECC point K := [ds](x2, y2), the L point as L := [r](x2, y2), the E point as E := [r]P1
            and the counter value respectively.

        C Function: Esys_Commit

        TPM Command: TPM2_Commit
        """
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        P1_cdata = _get_cdata(p1, TPM2B_ECC_POINT, "p1")
        s2_cdata = _get_cdata(s2, TPM2B_SENSITIVE_DATA, "s2")
        y2_cdata = _get_cdata(y2, TPM2B_ECC_PARAMETER, "y2")

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
            TPM2B_ECC_POINT(_get_dptr(K, lib.Esys_Free)),
            TPM2B_ECC_POINT(_get_dptr(L, lib.Esys_Free)),
            TPM2B_ECC_POINT(_get_dptr(E, lib.Esys_Free)),
            counter[0],
        )

    def ec_ephemeral(
        self,
        curve_id: TPM2_ECC_CURVE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ECC_POINT, int]:
        """Invoke the TPM2_EC_Ephemeral command.

        This function invokes the TPM2_EC_Ephemeral command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            curve_id (TPM2_ECC_CURVE): The curve for the computed ephemeral point .
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ECC_POINT, int] which is the Ephemeral public key Q := [r]G, known as Q,
            and the least-significant 16 bits of commitCount.

        C Function: Esys_EC_Ephemeral

        TPM Command: TPM2_EC_Ephemeral
        """

        _check_friendly_int(curve_id, "curve_id", TPM2_ECC_CURVE)
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        Q = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_EC_Ephemeral(
                self._ctx, session1, session2, session3, curve_id, Q, counter
            )
        )
        return (TPM2B_ECC_POINT(_get_dptr(Q, lib.Esys_Free)), counter[0])

    def verify_signature(
        self,
        key_handle: ESYS_TR,
        digest: Union[TPM2B_DIGEST, bytes, str],
        signature: TPMT_SIGNATURE,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMT_TK_VERIFIED:
        """Invoke the TPM2_VerifySignature command.

        This function invokes the TPM2_VerifySignature command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): Handle of public key that will be used in the validation.
            digest (Union[TPM2B_DIGEST, bytes, str]): Digest of the signed message.
            signature (TPMT_SIGNATURE): Signature to be tested.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPMT_TK_VERIFIED on successful verification of the signature.

        C Function: Esys_VerifySignature

        TPM Command: TPM2_VerifySignature
        """
        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        digest_cdata = _get_cdata(digest, TPM2B_DIGEST, "digest")
        signature_cdata = _get_cdata(signature, TPMT_SIGNATURE, "signature")

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
        return TPMT_TK_VERIFIED(_get_dptr(validation, lib.Esys_Free))

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
        """Invoke the TPM2_Sign command.

        This function invokes the TPM2_Sign command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR):
            digest (Union[TPM2B_DIGEST, bytes, str]): Digest to be signed.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for keyHandle is TPM2_ALG_NULL.
            validation (TPMT_TK_HASHCHECK): Proof that digest was created by the TPM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPMT_SIGNATURE the signature.

        C Function: Esys_Sign

        TPM Command: TPM2_Sign
        """

        _check_handle_type(key_handle, "key_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        digest_cdata = _get_cdata(digest, TPM2B_DIGEST, "digest")
        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")
        validation_cdata = _get_cdata(validation, TPMT_TK_HASHCHECK, "validation")

        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Sign(
                self._ctx,
                key_handle,
                session1,
                session2,
                session3,
                digest_cdata,
                in_scheme_cdata,
                validation_cdata,
                signature,
            )
        )
        return TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free))

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
        """Invoke the TPM2_SetCommandCodeAuditStatus command.

        This function invokes the TPM2_SetCommandCodeAuditStatus command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            audit_alg (TPM2_ALG): TPM2_Hash algorithm for the audit digest; if TPM2_ALG_NULL,
                then the hash is not changed.
            set_list (TPML_CC): List of commands that will be added to those that will be audited.
            clear_list (TPML_CC): List of commands that will no longer be audited.
            auth (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP} (optional). Default to ESYS_TR.OWNER
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_SetCommandCodeAuditStatus

        TPM Command: TPM2_SetCommandCodeAuditStatus
        """
        _check_handle_type(auth, "auth", expected=[ESYS_TR.OWNER, ESYS_TR.PLATFORM])

        _check_friendly_int(audit_alg, "audit_alg", TPM2_ALG)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        set_list_cdata = _get_cdata(set_list, TPML_CC, "set_list")
        clear_list_cdata = _get_cdata(clear_list, TPML_CC, "digest")

        _chkrc(
            lib.Esys_SetCommandCodeAuditStatus(
                self._ctx,
                auth,
                session1,
                session2,
                session3,
                audit_alg,
                set_list_cdata,
                clear_list_cdata,
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
        """Invoke the TPM2_PCR_Extend command.

        This function invokes the TPM2_PCR_Extend command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_handle (ESYS_TR): Handle of the PCR.
            digests (TPML_DIGEST_VALUES): List of tagged digest values to be extended.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PCR_Extend

        TPM Command: TPM2_PCR_Extend
        """

        _check_handle_type(pcr_handle, "pcr_handle")

        digests_cdata = _get_cdata(digests, TPML_DIGEST_VALUES, "digests")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PCR_Event command.

        This function invokes the TPM2_PCR_Event command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_handle (ESYS_TR): Handle of the PCR.
            event_data (Union[TPM2B_EVENT, bytes, str]): The event data.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPML_DIGEST_VALUES the digests.

        C Function: Esys_PCR_Event

        TPM Command: TPM2_PCR_Event
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _check_handle_type(pcr_handle, "pcr_handle")

        event_data_cdata = _get_cdata(event_data, TPM2B_EVENT, "event_data")

        digests = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_PCR_Event(
                self._ctx,
                pcr_handle,
                session1,
                session2,
                session3,
                event_data_cdata,
                digests,
            )
        )
        return TPML_DIGEST_VALUES(_get_dptr(digests, lib.Esys_Free))

    def pcr_read(
        self,
        pcr_selection_in: Union[TPML_PCR_SELECTION, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[int, TPML_PCR_SELECTION, TPML_DIGEST]:
        """Invoke the TPM2_PCR_Read command.

        This function invokes the TPM2_PCR_Read command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_selection_in (Union[TPML_PCR_SELECTION, str]): The selection of PCR to read.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[int, TPML_PCR_SELECTION, TPML_DIGEST] of the current value of the PCR update counter,
            the digests The PCR in the returned list and the contents of the PCR indicated in TPML_PCR_SELECTION.

        C Function: Esys_PCR_Read

        TPM Command: TPM2_PCR_Read
        """
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        pcr_selection_in_cdata = _get_cdata(
            pcr_selection_in, TPML_PCR_SELECTION, "pcr_selection_in"
        )

        pcr_update_counter = ffi.new("UINT32 *")
        pcr_selection_out = ffi.new("TPML_PCR_SELECTION **")
        pcr_values = ffi.new("TPML_DIGEST **")
        _chkrc(
            lib.Esys_PCR_Read(
                self._ctx,
                session1,
                session2,
                session3,
                pcr_selection_in_cdata,
                pcr_update_counter,
                pcr_selection_out,
                pcr_values,
            )
        )

        return (
            pcr_update_counter[0],
            TPML_PCR_SELECTION(_cdata=_get_dptr(pcr_selection_out, lib.Esys_Free)),
            TPML_DIGEST(_cdata=_get_dptr(pcr_values, lib.Esys_Free)),
        )

    def pcr_allocate(
        self,
        pcr_allocation: Union[TPML_PCR_SELECTION, str],
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[bool, int, int, int]:
        """Invoke the TPM2_PCR_Allocate command.

        This function invokes the TPM2_PCR_Allocate command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_allocation (Union[TPML_PCR_SELECTION, str]): The requested allocation.
            auth_handle (ESYS_TR): ESYS_TR.PLATFORM+{PP} (optional). Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[bool, int, int, int] of True if the allocation succeeded, the maximum number of PCR that
            may be in a bank, the number of octets required to satisfy the request, and number of octets available
            (Computed before the allocation) respectively.

        C Function: Esys_PCR_Allocate

        TPM Command: TPM2_PCR_Allocate
        """
        _check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        pcr_allocation_cdata = _get_cdata(
            pcr_allocation, TPML_PCR_SELECTION, "pcr_allocation"
        )

        allocation_success = ffi.new("TPMI_YES_NO *")
        max_pCR = ffi.new("UINT32 *")
        size_needed = ffi.new("UINT32 *")
        size_available = ffi.new("UINT32 *")
        _chkrc(
            lib.Esys_PCR_Allocate(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                pcr_allocation_cdata,
                allocation_success,
                max_pCR,
                size_needed,
                size_available,
            )
        )
        return (
            bool(allocation_success[0]),
            max_pCR[0],
            size_needed[0],
            size_available[0],
        )

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
        """Invoke the TPM2_PCR_SetAuthPolicy command.

        This function invokes the TPM2_PCR_SetAuthPolicy command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_policy (Union[TPM2B_DIGEST, bytes, str]): The desired authPolicy.
            hash_alg (TPM2_ALG): The hash algorithm of the policy.
            pcr_num (ESYS_TR): The PCR for which the policy is to be set.
            auth_handle (ESYS_TR): ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PCR_SetAuthPolicy

        TPM Command: TPM2_PCR_SetAuthPolicy
        """

        _check_handle_type(auth_handle, "auth_handle", expected=[ESYS_TR.PLATFORM])

        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)
        _check_friendly_int(pcr_num, "pcr_num", ESYS_TR)

        auth_policy_cdata = _get_cdata(auth_policy, TPM2B_DIGEST, "auth_policy")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PCR_SetAuthPolicy(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                auth_policy_cdata,
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
        """Invoke the TPM2_PCR_SetAuthValue command.

        This function invokes the TPM2_PCR_SetAuthValue command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_handle (ESYS_TR): Handle for a PCR that may have an authorization value set.
            auth (Union[TPM2B_DIGEST, bytes, str]): The desired authorization value.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PCR_SetAuthValue

        TPM Command: TPM2_PCR_SetAuthValue
        """

        _check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        auth_cdata = _get_cdata(auth, TPM2B_DIGEST, "auth")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PCR_Reset command.

        This function invokes the TPM2_PCR_Reset command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            pcr_handle (ESYS_TR): The PCR to reset.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PCR_Reset

        TPM Command: TPM2_PCR_Reset
        """

        _check_friendly_int(pcr_handle, "pcr_handle", ESYS_TR)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PolicySigned command.

        This function invokes the TPM2_PolicySigned command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_object (ESYS_TR): Handle for a key that will validate the signature.
            policy_session (ESYS_TR): Handle for the policy session being extended.
            nonce_tpm (Union[TPM2B_NONCE, bytes, str]): The policy nonce for the session.
            cp_hash_a (Union[TPM2B_DIGEST, bytes, str]): Digest of the command parameters to which this
                authorization is limited.
            policy_ref (Union[TPM2B_NONCE, bytes, str]): policyRef A reference to a policy relating to the authorization
                - may be the Empty Buffer.
            expiration (int): Time when authorization will expire, measured in seconds from the time that nonceTPM was
                generated.
            auth (TPMT_SIGNATURE): Signed authorization (not optional).
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH] which is the timeout, an implementation-specific time value,
            used to indicate to the TPM when the ticket expires and the policy_ticket, a which is produced if
            the command succeeds and expiration in the command was non-zero; this ticket will use the
            TPMT_ST_AUTH_SIGNED structure tag. See 23.2.5.

        C Function: Esys_PolicySigned

        TPM Command: TPM2_PolicySigned
        """

        _check_handle_type(auth_object, "auth_object")

        _check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        nonce_tPM_cdata = _get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cp_hash_a_cdata = _get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policy_ref_cdata = _get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        auth_cdata = _get_cdata(auth, TPMT_SIGNATURE, "auth")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policy_ticket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySigned(
                self._ctx,
                auth_object,
                policy_session,
                session1,
                session2,
                session3,
                nonce_tPM_cdata,
                cp_hash_a_cdata,
                policy_ref_cdata,
                expiration,
                auth_cdata,
                timeout,
                policy_ticket,
            )
        )
        return (
            TPM2B_TIMEOUT(_get_dptr(timeout, lib.Esys_Free)),
            TPMT_TK_AUTH(_get_dptr(policy_ticket, lib.Esys_Free)),
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
        """Invoke the TPM2_PolicySecret command.

        This function invokes the TPM2_PolicySecret command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): Handle for an entity providing the authorization.
            policy_session (ESYS_TR): Handle for the policy session being extended.
            nonce_tpm (Union[TPM2B_NONCE, bytes, str]): The policy nonce for the session.
            cp_hash_a (Union[TPM2B_DIGEST, bytes, str]): Digest of the command parameters to which this
                authorization is limited.
            policy_ref (Union[TPM2B_NONCE, bytes, str]): policyRef A reference to a policy relating to the authorization
                - may be the Empty Buffer.
            expiration (int): Time when authorization will expire, measured in seconds from the time that nonceTPM was
                generated.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_TIMEOUT, TPMT_TK_AUTH] which is the timeout, an implementation-specific time value,
            used to indicate to the TPM when the ticket expires and the policy_ticket, a which is produced if
            the command succeeds and expiration in the command was non-zero; this ticket will use the
            TPMT_ST_AUTH_SIGNED structure tag. See 23.2.5.

        C Function: Esys_PolicySecret

        TPM Command: TPM2_PolicySecret
        """

        _check_handle_type(policy_session, "policy_session")

        if not isinstance(expiration, int):
            raise TypeError(
                f"expected expiration to be type int, got {type(expiration)}"
            )

        _check_friendly_int(auth_handle, "auth_handle", ESYS_TR)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        nonce_tPM_cdata = _get_cdata(nonce_tpm, TPM2B_NONCE, "nonce_tpm")
        cp_hash_a_cdata = _get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policy_ref_cdata = _get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policy_ticket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySecret(
                self._ctx,
                auth_handle,
                policy_session,
                session1,
                session2,
                session3,
                nonce_tPM_cdata,
                cp_hash_a_cdata,
                policy_ref_cdata,
                expiration,
                timeout,
                policy_ticket,
            )
        )
        return (
            TPM2B_TIMEOUT(_get_dptr(timeout, lib.Esys_Free)),
            TPMT_TK_AUTH(_get_dptr(policy_ticket, lib.Esys_Free)),
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
        """Invoke the TPM2_PolicyTicket command.

        This function invokes the TPM2_PolicyTicket command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            timeout (TPM2B_TIMEOUT): Time when authorization will expire.
            cp_hash_a (Union[TPM2B_DIGEST, bytes, str]): Digest of the command parameters to which this
                authorization is limited.
            policy_ref (Union[TPM2B_NONCE, bytes, str]): policyRef A reference to a policy relating to the authorization
                - may be the Empty Buffer.
            auth_name (Union[TPM2B_NAME, bytes, str]): Name of the object that provided the authorization.
            ticket (TPMT_TK_AUTH): An authorization ticket returned by the TPM in response to a
                TPM2_PolicySigned() or TPM2_PolicySecret().
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyTicket

        TPM Command: TPM2_PolicyTicket
        """
        _check_handle_type(policy_session, "policy_session")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        timeout_cdata = _get_cdata(timeout, TPM2B_TIMEOUT, "timeout")
        cp_hash_a_cdata = _get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")
        policy_ref_cdata = _get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        auth_name_cdata = _get_cdata(auth_name, TPM2B_NAME, "auth_name")
        ticket_cdata = _get_cdata(ticket, TPMT_TK_AUTH, "ticket")

        _chkrc(
            lib.Esys_PolicyTicket(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                timeout_cdata,
                cp_hash_a_cdata,
                policy_ref_cdata,
                auth_name_cdata,
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
        """Invoke the TPM2_PolicyOr command.

        This function invokes the TPM2_PolicyOr command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            p_hash_list (TPML_DIGEST): The list of hashes to check for a match.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyOr

        TPM Command: TPM2_PolicyOr
        """

        _check_handle_type(policy_session, "policy_session")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        p_hash_list_cdata = _get_cdata(p_hash_list, TPML_DIGEST, "p_hash_list")

        _chkrc(
            lib.Esys_PolicyOR(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                p_hash_list_cdata,
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
        """Invoke the TPM2_PolicyPCR command.

        This function invokes the TPM2_PolicyPCR command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            pcr_digest (Union[TPM2B_DIGEST, bytes, str]): Expected digest value of the selected PCR using the
                hash algorithm of the session; may be zero length.
            pcrs (Union[TPML_PCR_SELECTION, str]): The PCR to include in the check digest.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyPCR

        TPM Command: TPM2_PolicyPCR
        """

        _check_handle_type(policy_session, "policy_session")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        pcr_digest_cdata = _get_cdata(pcr_digest, TPM2B_DIGEST, "pcr_digest")
        pcrs_cdata = _get_cdata(pcrs, TPML_PCR_SELECTION, "pcrs")

        _chkrc(
            lib.Esys_PolicyPCR(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                pcr_digest_cdata,
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
        """Invoke the TPM2_PolicyLocality command.

        This function invokes the TPM2_PolicyLocality command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            locality (int): The allowed localities for the policy.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyLocality

        TPM Command: TPM2_PolicyLocality
        """

        _check_handle_type(policy_session, "policy_session")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PolicyNV command.

        This function invokes the TPM2_PolicyNV command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): Handle indicating the source of the authorization value.
            nv_index (ESYS_TR): The NV Index of the area to read.
            policy_session (ESYS_TR): Handle for the policy session being extended.
            operand_b (TPM2B_OPERAND): The second operand.
            operation (TPM2_EO): The comparison to make.
            offset (int): The offset in the NV Index for the start of operand A. (optional). Defaults to 0.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyNV

        TPM Command: TPM2_PolicyNV
        """
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")

        _check_handle_type(policy_session, "policy_session")

        operand_b_cdata = _get_cdata(operand_b, TPM2B_OPERAND, "operand_b")

        _check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNV(
                self._ctx,
                auth_handle,
                nv_index,
                policy_session,
                session1,
                session2,
                session3,
                operand_b_cdata,
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
        """Invoke the TPM2_PolicyCounterTimer command.

        This function invokes the TPM2_PolicyCounterTimer command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            operand_b (TPM2B_OPERAND): The second operand.
            operation (TPM2_EO): The comparison to make.
            offset (int): The offset in TPMS_TIME_INFO structure for the start of operand A. (optional).
                Defaults to 0.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyCounterTimer

        TPM Command: TPM2_PolicyCounterTimer
        """

        _check_handle_type(policy_session, "policy_session")

        operand_b_cdata = _get_cdata(operand_b, TPM2B_OPERAND, "operand_b")

        _check_friendly_int(operation, "operation", TPM2_EO)

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got {type(offset)}")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCounterTimer(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                operand_b_cdata,
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
        """Invoke the TPM2_PolicyCommandCode command.

        This function invokes the TPM2_PolicyCommandCode command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            code (TPM2_CC): The allowed commandCode.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyCommandCode

        TPM Command: TPM2_PolicyCommandCode
        """

        _check_handle_type(policy_session, "policy_session")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _check_friendly_int(code, "code", TPM2_CC)

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
        """Invoke the TPM2_PolicyPhysicalPresence command.

        This function invokes the TPM2_PolicyPhysicalPresence command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyPhysicalPresence

        TPM Command: TPM2_PolicyPhysicalPresence
        """

        _check_handle_type(policy_session, "policy_session")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PolicyCpHash command.

        This function invokes the TPM2_PolicyCpHash command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            cp_hash_a (Union[TPM2B_DIGEST, bytes, str]): The cpHash added to the policy.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyCpHash

        TPM Command: TPM2_PolicyCpHash
        """

        _check_handle_type(policy_session, "policy_session")

        cp_hash_a_cdata = _get_cdata(cp_hash_a, TPM2B_DIGEST, "cp_hash_a")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyCpHash(
                self._ctx, policy_session, session1, session2, session3, cp_hash_a_cdata
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
        """Invoke the TPM2_PolicyNameHash command.

        This function invokes the TPM2_PolicyNameHash command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            name_hash (Union[TPM2B_DIGEST, bytes, str]): The digest to be added to the policy.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyNameHash

        TPM Command: TPM2_PolicyNameHash
        """
        _check_handle_type(policy_session, "policy_session")

        name_hash_cdata = _get_cdata(name_hash, TPM2B_DIGEST, "name_hash")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyNameHash(
                self._ctx, policy_session, session1, session2, session3, name_hash_cdata
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
        """Invoke the TPM2_PolicyDuplicationSelect command.

        This function invokes the TPM2_PolicyDuplicationSelect command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            object_name (Union[TPM2B_NAME, bytes, str]): The Name of the object to be duplicated.
            new_parent_name (Union[TPM2B_NAME, bytes, str]): The Name of the new parent.
            include_object (bool): If YES, the objectName will be included in the
                value in policySession->policyDigest, optional. Defaults to False.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyDuplicationSelect

        TPM Command: TPM2_PolicyDuplicationSelect
        """

        _check_handle_type(policy_session, "policy_session")

        object_name_cdata = _get_cdata(object_name, TPM2B_NAME, "object_name")
        new_parent_name_cdata = _get_cdata(
            new_parent_name, TPM2B_NAME, "new_parent_name"
        )

        if not isinstance(include_object, bool):
            raise TypeError(
                f"Expected include_object to be type bool, got {type(include_object)}"
            )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyDuplicationSelect(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                object_name_cdata,
                new_parent_name_cdata,
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
        """Invoke the TPM2_PolicyAuthorize command.

        This function invokes the TPM2_PolicyAuthorize command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            approved_policy (Union[TPM2B_DIGEST, bytes, str]): Digest of the policy being approved.
            policy_ref (Union[TPM2B_NONCE, bytes, str]): A policy qualifier.
            key_sign (Union[TPM2B_NAME, bytes, str]): Name of a key that can sign a policy addition.
            check_ticket (TPMT_TK_VERIFIED): Ticket validating that approvedPolicy and policyRef
                were signed by keySign.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyAuthorize

        TPM Command: TPM2_PolicyAuthorize
        """

        _check_handle_type(policy_session, "policy_session")

        approved_policy_cdata = _get_cdata(
            approved_policy, TPM2B_DIGEST, "approved_policy"
        )
        policy_ref_cdata = _get_cdata(policy_ref, TPM2B_NONCE, "policy_ref")
        key_sign_cdata = _get_cdata(key_sign, TPM2B_NAME, "key_sign")
        check_ticket_cdata = _get_cdata(check_ticket, TPMT_TK_VERIFIED, "check_ticket")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyAuthorize(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                approved_policy_cdata,
                policy_ref_cdata,
                key_sign_cdata,
                check_ticket_cdata,
            )
        )

    def policy_auth_value(
        self,
        policy_session: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_PolicyAuthValue command.

        This function invokes the TPM2_PolicyAuthValue command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyAuthValue

        TPM Command: TPM2_PolicyAuthValue
        """

        _check_handle_type(policy_session, "policy_session")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PolicyPassword command.

        This function invokes the TPM2_PolicyPassword command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyPassword

        TPM Command: TPM2_PolicyPassword
        """

        _check_handle_type(policy_session, "policy_session")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
    ) -> TPM2B_DIGEST:
        """Invoke the TPM2_PolicyGetDigest command.

        This function invokes the TPM2_PolicyGetDigest command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            The current value of the policySession->policyDigest as a TPM2B_DIGEST.

        C Function: Esys_PolicyGetDigest

        TPM Command: TPM2_PolicyGetDigest
        """
        _check_handle_type(policy_session, "policy_session")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        policy_digest = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_PolicyGetDigest(
                self._ctx, policy_session, session1, session2, session3, policy_digest
            )
        )
        return TPM2B_DIGEST(_get_dptr(policy_digest, lib.Esys_Free))

    def policy_nv_written(
        self,
        policy_session: ESYS_TR,
        written_set: bool = True,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_PolicyNvWritten command.

        This function invokes the TPM2_PolicyNvWritten command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            written_set (bool): True if NV Index is required to have been written, False otherwise. Defaults to True.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyNvWritten

        TPM Command: TPM2_PolicyNvWritten
        """

        _check_handle_type(policy_session, "policy_session")

        if not isinstance(written_set, bool):
            raise TypeError(
                f"Expected written_set to be type bool, got {type(written_set)}"
            )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_PolicyTemplate command.

        This function invokes the TPM2_PolicyTemplate command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            policy_session (ESYS_TR): Handle for the policy session being extended.
            template_hash (Union[TPM2B_DIGEST, bytes, str]): The digest to be added to the policy.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyTemplate

        TPM Command: TPM2_PolicyTemplate
        """

        _check_handle_type(policy_session, "policy_session")

        template_hash_cdata = _get_cdata(template_hash, TPM2B_DIGEST, "template_hash")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_PolicyTemplate(
                self._ctx,
                policy_session,
                session1,
                session2,
                session3,
                template_hash_cdata,
            )
        )

    def policy_authorize_nv(
        self,
        nv_index: ESYS_TR,
        policy_session: ESYS_TR,
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_PolicyAuthorizeNV command.

        This function invokes the TPM2_PolicyAuthorizeNV command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index of the area to read.
            policy_session (ESYS_TR): Handle for the policy session being extended.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization value. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PolicyAuthorizeNV

        TPM Command: TPM2_PolicyAuthorizeNV
        """

        if auth_handle is None:
            auth_handle = nv_index

        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(policy_session, "policy_session")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        in_sensitive: Optional[TPM2B_SENSITIVE_CREATE],
        in_public: Union[TPM2B_PUBLIC, str] = "rsa2048",
        primary_handle: ESYS_TR = ESYS_TR.OWNER,
        outside_info: Union[TPM2B_DATA, bytes, str] = TPM2B_DATA(),
        creation_pcr: Union[TPML_PCR_SELECTION, str] = TPML_PCR_SELECTION(),
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[
        ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION
    ]:
        """Invoke the TPM2_CreatePrimary command.

        This function invokes the TPM2_CreatePrimary command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            in_sensitive (TPM2B_SENSITIVE_CREATE): The sensitive data, see TPM 2.0 Part 1 Sensitive Values. Accepts
                None for an empty TPM2B_SENSITIVE_CREATE.
            in_public (Union[TPM2B_PUBLIC, str]): The public template. Defaults to "rsa2048".
            primary_handle (ESYS_TR): ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER, ESYS_TR.PLATFORM or ESYS_TR.NULL.
                Defaults to ESYS_TR.OWNER.
            outside_info (Union[TPM2B_DATA, bytes, str]): Data that will be included in the creation data for
                this object to provide permanent, verifiable linkage between this object and some object owner data.
                Defaults to an empty TPM2B_DATA.
            creation_pcr (Union[TPML_PCR_SELECTION, str]): PCR that will be used in creation data. Defaults to an empty
                TPML_PCR_SELECTION().
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION] which is the ESYS_TR handle of ESYS resource for TPM2_HANDLE,
            the public portion of the created object, the creation data and digest of creation data using the nameAlg of
            of the object respectively.

        C Function: Esys_CreatePrimary

        TPM Command: TPM2_CreatePrimary
        """

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        in_public_cdata = _get_cdata(
            in_public,
            TPM2B_PUBLIC,
            "in_public",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )

        if in_sensitive is None:
            in_sensitive = TPM2B_SENSITIVE_CREATE()
        in_sensitive_cdata = _get_cdata(
            in_sensitive, TPM2B_SENSITIVE_CREATE, "in_sensitive"
        )
        outside_info_cdata = _get_cdata(outside_info, TPM2B_DATA, "outside_info")
        creation_pCR_cdata = _get_cdata(
            creation_pcr, TPML_PCR_SELECTION, "creation_pcr"
        )

        object_handle = ffi.new("ESYS_TR *")
        out_public = ffi.new("TPM2B_PUBLIC **")
        creation_data = ffi.new("TPM2B_CREATION_DATA **")
        creation_hash = ffi.new("TPM2B_DIGEST **")
        creation_ticket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_CreatePrimary(
                self._ctx,
                primary_handle,
                session1,
                session2,
                session3,
                in_sensitive_cdata,
                in_public_cdata,
                outside_info_cdata,
                creation_pCR_cdata,
                object_handle,
                out_public,
                creation_data,
                creation_hash,
                creation_ticket,
            )
        )

        return (
            ESYS_TR(object_handle[0]),
            TPM2B_PUBLIC(_cdata=_get_dptr(out_public, lib.Esys_Free)),
            TPM2B_CREATION_DATA(_cdata=_get_dptr(creation_data, lib.Esys_Free)),
            TPM2B_DIGEST(_cdata=_get_dptr(creation_hash, lib.Esys_Free)),
            TPMT_TK_CREATION(_cdata=_get_dptr(creation_ticket, lib.Esys_Free)),
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
        """Invoke the TPM2_HierarchyControl command.

        This function invokes the TPM2_HierarchyControl command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER or ESYS_TR.PLATFORM.
            enable (ESYS_TR): The enable being modified.
            state (bool): True if the enable should be SET, False if the enable should be CLEAR.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_HierarchyControl

        TPM Command: TPM2_HierarchyControl
        """

        _check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER, ESYS_TR.PLATFORM),
        )

        _check_handle_type(
            enable,
            "enable",
            expected=(ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER, ESYS_TR.PLATFORM),
        )
        enable = ESAPI._fixup_hierarchy(enable)

        if not isinstance(state, bool):
            raise TypeError(f"Expected state to be a bool, got {type(state)}")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_SetPrimaryPolicy command.

        This function invokes the TPM2_SetPrimaryPolicy command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER or ESYS_TR.PLATFORM.
            auth_policy (Union[TPM2B_DIGEST, bytes, str]): authPolicy An authorization policy digest; may be the
                empty buffer.
            hash_alg (TPM2_ALG): The hash algorithm to use for the policy.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_SetPrimaryPolicy

        TPM Command: TPM2_SetPrimaryPolicy
        """

        _check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER, ESYS_TR.PLATFORM),
        )
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        auth_policy_cdata = _get_cdata(auth_policy, TPM2B_DIGEST, "auth_policy")
        _check_friendly_int(hash_alg, "hash_alg", TPM2_ALG)

        _chkrc(
            lib.Esys_SetPrimaryPolicy(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                auth_policy_cdata,
                hash_alg,
            )
        )

    def change_pps(
        self,
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_ChangePPS command.

        This function invokes the TPM2_ChangePPS command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_ChangePPS

        TPM Command: TPM2_ChangePPS
        """

        _check_handle_type(auth_handle, "auth_handle", expected=(ESYS_TR.PLATFORM,))

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangePPS(self._ctx, auth_handle, session1, session2, session3))

    def change_eps(
        self,
        auth_handle: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_ChangeEPS command.

        This function invokes the TPM2_ChangeEPS command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_ChangeEPS

        TPM Command: TPM2_ChangeEPS
        """

        _check_handle_type(auth_handle, "auth_handle", expected=(ESYS_TR.PLATFORM,))

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(lib.Esys_ChangeEPS(self._ctx, auth_handle, session1, session2, session3))

    def clear(
        self,
        auth_handle: ESYS_TR,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_Clear command.

        This function invokes the TPM2_Clear command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.LOCKOUT or ESYS_TR.PLATFORM+{PP}.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_Clear

        TPM Command: TPM2_Clear
        """

        _check_handle_type(
            auth_handle, "auth_handle", expected=(ESYS_TR.PLATFORM, ESYS_TR.LOCKOUT)
        )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(lib.Esys_Clear(self._ctx, auth_handle, session1, session2, session3))

    def clear_control(
        self,
        auth: ESYS_TR,
        disable: bool,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_ClearControl command.

        This function invokes the TPM2_ClearControl command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth (ESYS_TR): ESYS_TR.LOCKOUT or ESYS_TR.PLATFORM+{PP}.
            disable (bool): True if the disableOwnerClear flag is to be SET, False if the flag is to be CLEAR.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_ClearControl

        TPM Command: TPM2_ClearControl
        """

        _check_handle_type(auth, "auth", expected=(ESYS_TR.PLATFORM, ESYS_TR.LOCKOUT))

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_HierarchyChangeAuth command.

        This function invokes the TPM2_HierarchyChangeAuth command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): ESYS_TR.LOCKOUT, ESYS_TR.ENDORSEMENT, ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}.
            new_auth (Union[TPM2B_AUTH, bytes, str]): New authorization value.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_HierarchyChangeAuth

        TPM Command: TPM2_HierarchyChangeAuth
        """

        _check_handle_type(
            auth_handle,
            "auth_handle",
            expected=(
                ESYS_TR.LOCKOUT,
                ESYS_TR.ENDORSEMENT,
                ESYS_TR.OWNER,
                ESYS_TR.PLATFORM,
            ),
        )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        new_auth_cdata = _get_cdata(new_auth, TPM2B_AUTH, "new_auth")

        _chkrc(
            lib.Esys_HierarchyChangeAuth(
                self._ctx, auth_handle, session1, session2, session3, new_auth_cdata,
            )
        )

    def dictionary_attack_lock_reset(
        self,
        lock_handle: ESYS_TR = ESYS_TR.LOCKOUT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_DictionaryAttackLockReset command.

        This function invokes the TPM2_DictionaryAttackLockReset command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            lock_handle (ESYS_TR): ESYS_TR.LOCKOUT. Defaults to ESYS_TR.LOCKOUT.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_DictionaryAttackLockReset

        TPM Command: TPM2_DictionaryAttackLockReset
        """

        _check_handle_type(lock_handle, "lock_handle", expected=(ESYS_TR.LOCKOUT,))
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
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
        lock_handle: ESYS_TR = ESYS_TR.LOCKOUT,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_DictionaryAttackParameters command.

        This function invokes the TPM2_DictionaryAttackParameters command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            new_max_tries (int): Count of authorization failures before the lockout is imposed.
            new_recovery_time (int): Time in seconds before the authorization failure count
                is automatically decremented.
            lockout_recovery (int): Time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed.
            lock_handle (ESYS_TR): ESYS_TR.LOCKOUT. Defaults to ESYS_TR.LOCKOUT.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_DictionaryAttackParameters

        TPM Command: TPM2_DictionaryAttackParameters
        """

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

        _check_handle_type(lock_handle, "lock_handle", expected=(ESYS_TR.LOCKOUT,))
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
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
        """Invoke the TPM2_PP_Commands command.

        This function invokes the TPM2_PP_Commands command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            set_list (TPML_CC): List of commands to be added to those that will require
                that Physical Presence be asserted.
            clear_list (TPML_CC): clearList List of commands that will no longer require that
                Physical Presence be asserted.
            auth (ESYS_TR): ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_PP_Commands

        TPM Command: TPM2_PP_Commands
        """

        _check_handle_type(auth, "auth", expected=(ESYS_TR.PLATFORM,))
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        set_list_cdata = _get_cdata(set_list, TPML_CC, "set_list")
        clear_list_cdata = _get_cdata(clear_list, TPML_CC, "clear_list")
        _chkrc(
            lib.Esys_PP_Commands(
                self._ctx,
                auth,
                session1,
                session2,
                session3,
                set_list_cdata,
                clear_list_cdata,
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
        """Invoke the TPM2_SetAlgorithmSet command.

        This function invokes the TPM2_SetAlgorithmSet command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            algorithm_set (Union[List[int], int]): A TPM vendor-dependent value indicating the
                algorithm set selection.
            auth_handle (ESYS_TR): ESYS_TR.PLATFORM. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_SetAlgorithmSet

        TPM Command: TPM2_SetAlgorithmSet
        """

        _check_handle_type(auth_handle, "auth_handle", expected=(ESYS_TR.PLATFORM,))
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_SetAlgorithmSet(
                self._ctx, auth_handle, session1, session2, session3, algorithm_set
            )
        )

    def field_upgrade_start(
        self,
        key_handle: ESYS_TR,
        fu_digest: Union[TPM2B_DIGEST, bytes, str],
        manifest_signature: TPMT_SIGNATURE,
        authorization: ESYS_TR = ESYS_TR.PLATFORM,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_FieldUpgradeStart command.

        This function invokes the TPM2_FieldUpgradeStart command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            key_handle (ESYS_TR): Handle of a public area that contains the TPM Vendor
                Authorization Key that will be used to validate manifestSignature.
            fu_digest (Union[TPM2B_DIGEST, bytes, str]): Digest of the first block in the field upgrade sequence.
            manifest_signature (TPMT_SIGNATURE): Signature over fuDigest using the key
                associated with keyHandle (not optional).
            authorization (ESYS_TR): ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_FieldUpgradeStart

        TPM Command: TPM2_FieldUpgradeStart
        """

        _check_handle_type(authorization, "authorization")
        _check_handle_type(key_handle, "key_handle")
        fu_digest_cdata = _get_cdata(fu_digest, TPM2B_DIGEST, "fu_digest")
        manifest_signature_cdata = _get_cdata(
            manifest_signature, TPMT_SIGNATURE, "manifest_signature"
        )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_FieldUpgradeStart(
                self._ctx,
                authorization,
                key_handle,
                session1,
                session2,
                session3,
                fu_digest_cdata,
                manifest_signature_cdata,
            )
        )

    def field_upgrade_data(
        self,
        fu_data: Union[TPM2B_MAX_BUFFER, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPMT_HA, TPMT_HA]:
        """Invoke the TPM2_FieldUpgradeData command.

        This function invokes the TPM2_FieldUpgradeData command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            fu_data (Union[TPM2B_MAX_BUFFER, bytes, str]): Field upgrade image data.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPMT_HA, TPMT_HA] which is the tagged digest of the next block and the
            tagged digest of the first block of the sequence respectively.

        C Function: Esys_FieldUpgradeData

        TPM Command: TPM2_FieldUpgradeData
        """

        fu_data_cdata = _get_cdata(fu_data, TPM2B_MAX_BUFFER, "fu_data")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        next_digest = ffi.new("TPMT_HA **")
        first_digest = ffi.new("TPMT_HA **")
        _chkrc(
            lib.Esys_FieldUpgradeData(
                self._ctx,
                session1,
                session2,
                session3,
                fu_data_cdata,
                next_digest,
                first_digest,
            )
        )
        return (
            TPMT_HA(_get_dptr(next_digest, lib.Esys_Free)),
            TPMT_HA(_get_dptr(first_digest, lib.Esys_Free)),
        )

    def firmware_read(
        self,
        sequence_number: int,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_MAX_BUFFER:
        """Invoke the TPM2_FirmwareRead command.

        This function invokes the TPM2_FirmwareRead command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sequence_number (int):  sequenceNumber The number of previous calls to this command in this sequence.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_MAX_BUFFER which is the field upgrade image data.

        C Function: Esys_FirmwareRead

        TPM Command: TPM2_FirmwareRead
        """

        if not isinstance(sequence_number, int):
            raise TypeError(
                f"Expected sequence_number to be an int, got {type(sequence_number)}"
            )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        fu_data = ffi.new("TPM2B_MAX_BUFFER **")
        _chkrc(
            lib.Esys_FirmwareRead(
                self._ctx, session1, session2, session3, sequence_number, fu_data
            )
        )
        return TPM2B_MAX_BUFFER(_get_dptr(fu_data, lib.Esys_Free))

    def context_save(self, save_handle: ESYS_TR) -> TPMS_CONTEXT:
        """Invoke the TPM2_ContextSave command.

        This function invokes the TPM2_ContextSave command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            save_handle (ESYS_TR): Handle of the resource to save.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPMS_CONTEXT which is the saved save_handle data.

        C Function: Esys_ContextSave

        TPM Command: TPM2_ContextSave
        """

        _check_handle_type(save_handle, "save_handle")
        context = ffi.new("TPMS_CONTEXT **")
        _chkrc(lib.Esys_ContextSave(self._ctx, save_handle, context))
        return TPMS_CONTEXT(_get_dptr(context, lib.Esys_Free))

    def context_load(self, context: TPMS_CONTEXT) -> ESYS_TR:
        """Invoke the TPM2_ContextLoad command.

        This function invokes the TPM2_ContextLoad command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            context (TPMS_CONTEXT): The context blob.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR which is the handle to the loaded data.

        C Function: Esys_ContextLoad

        TPM Command: TPM2_ContextLoad
        """

        context_cdata = _get_cdata(context, TPMS_CONTEXT, "context")
        loaded_handle = ffi.new("ESYS_TR *")
        _chkrc(lib.Esys_ContextLoad(self._ctx, context_cdata, loaded_handle))

        return ESYS_TR(loaded_handle[0])

    def flush_context(self, flush_handle: ESYS_TR) -> None:
        """Invoke the TPM2_FlushContext command.

        This function invokes the TPM2_FlushContext command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            flush_handle (ESYS_TR): The handle of the item to flush.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_FlushContext

        TPM Command: TPM2_FlushContext
        """

        _check_handle_type(flush_handle, "flush_handle")
        _chkrc(lib.Esys_FlushContext(self._ctx, flush_handle))

    def evict_control(
        self,
        auth: ESYS_TR,
        object_handle: ESYS_TR,
        persistent_handle: int,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Invoke the TPM2_EvictControl command.

        This function invokes the TPM2_EvictControl command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}.
            object_handle (ESYS_TR): The handle of a loaded object.
            persistent_handle (int): If objectHandle is a transient object handle, then this is the persistent
                handle for the object.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR handle of ESYS resource for TPM2_HANDLE.

        C Function: Esys_EvictControl

        TPM Command: TPM2_EvictControl
        """

        _check_handle_type(auth, "auth", expected=(ESYS_TR.OWNER, ESYS_TR.PLATFORM))
        _check_handle_type(object_handle, "object_handle")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        new_object_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_EvictControl(
                self._ctx,
                auth,
                object_handle,
                session1,
                session2,
                session3,
                persistent_handle,
                new_object_handle,
            )
        )

        return ESYS_TR(new_object_handle[0])

    def read_clock(
        self,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPMS_TIME_INFO:
        """Invoke the TPM2_ReadClock command.

        This function invokes the TPM2_ReadClock command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            The current time as a TPMS_TIME_INFO.

        C Function: Esys_ReadClock

        TPM Command: TPM2_ReadClock
        """
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        current_time = ffi.new("TPMS_TIME_INFO **")
        _chkrc(
            lib.Esys_ReadClock(self._ctx, session1, session2, session3, current_time)
        )
        return TPMS_TIME_INFO(_get_dptr(current_time, lib.Esys_Free))

    def clock_set(
        self,
        new_time: int,
        auth: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_ClockSet command.

        This function invokes the TPM2_ClockSet command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            new_time (int): New Clock setting in milliseconds.
            auth (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.OWNER.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_ClockSet

        TPM Command: TPM2_ClockSet
        """

        _check_handle_type(auth, "auth")

        if not isinstance(new_time, int):
            raise TypeError(f"Expected new_time to be an int, got {type(new_time)}")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        _chkrc(
            lib.Esys_ClockSet(self._ctx, auth, session1, session2, session3, new_time)
        )

    def clock_rate_adjust(
        self,
        rate_adjust: TPM2_CLOCK,
        auth: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_ClockRateAdjust command.

        This function invokes the TPM2_ClockRateAdjust command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            rate_adjust (TPM2_CLOCK): Adjustment to current Clock update rate.
            auth (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.OWNER.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_ClockRateAdjust

        TPM Command: TPM2_ClockRateAdjust
        """

        _check_handle_type(auth, "auth", expected=(ESYS_TR.OWNER, ESYS_TR.PLATFORM))

        _check_friendly_int(rate_adjust, "rate_adjustvarname", TPM2_CLOCK)

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        """Invoke the TPM2_GetCapability command.

        This function invokes the TPM2_GetCapability command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            capability (TPM2_CAP): Group selection; determines the format of the response.
            prop (int): Further definition of information.
            property_count (int): Number of properties of the indicated type to return. Defaults to 1.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[bool, TPMS_CAPABILITY_DATA] which is the Flag to indicate if there are more values of this type
            and the capability data respectively.

        C Function: Esys_GetCapability

        TPM Command: TPM2_GetCapability
        """

        _check_friendly_int(capability, "capability", TPM2_CAP)

        if not isinstance(prop, int):
            raise TypeError(f"Expected prop to be an int, got {type(prop)}")

        if not isinstance(property_count, int):
            raise TypeError(
                f"Expected property_count to be an int, got {type(property_count)}"
            )

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        more_data = ffi.new("TPMI_YES_NO *")
        capability_data = ffi.new("TPMS_CAPABILITY_DATA **")
        _chkrc(
            lib.Esys_GetCapability(
                self._ctx,
                session1,
                session2,
                session3,
                capability,
                prop,
                property_count,
                more_data,
                capability_data,
            )
        )
        return (
            bool(more_data[0]),
            TPMS_CAPABILITY_DATA(_get_dptr(capability_data, lib.Esys_Free)),
        )

    def test_parms(
        self,
        parameters: TPMT_PUBLIC_PARMS,
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_TestParms command.

        This function invokes the TPM2_TestParms command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            parameters (TPMT_PUBLIC_PARMS): Algorithm parameters to be validated.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_TestParms

        TPM Command: TPM2_TestParms
        """

        parameters_cdata = _get_cdata(parameters, TPMT_PUBLIC_PARMS, "parameters")
        _chkrc(
            lib.Esys_TestParms(
                self._ctx, session1, session2, session3, parameters_cdata
            )
        )

    def nv_define_space(
        self,
        auth: Union[TPM2B_AUTH, bytes, str, None],
        public_info: TPM2B_NV_PUBLIC,
        auth_handle: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> ESYS_TR:
        """Invoke the TPM2_NV_DefineSpace command.

        This function invokes the TPM2_NV_DefineSpace command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth (Union[TPM2B_AUTH, bytes, str, None]): The authorization value.
            public_info (TPM2B_NV_PUBLIC): The public parameters of the NV area.
            auth_handle (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.OWNER.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            An ESYS_TR handle of ESYS resource for TPM2_HANDLE.

        C Function: Esys_NV_DefineSpace

        TPM Command: TPM2_NV_DefineSpace
        """

        _check_handle_type(
            auth_handle, "auth_handle", expected=(ESYS_TR.OWNER, ESYS_TR.PLATFORM)
        )
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        auth_cdata = _get_cdata(auth, TPM2B_AUTH, "auth", allow_none=True)
        public_info_cdata = _get_cdata(public_info, TPM2B_NV_PUBLIC, "public_info")
        nv_handle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_NV_DefineSpace(
                self._ctx,
                auth_handle,
                session1,
                session2,
                session3,
                auth_cdata,
                public_info_cdata,
                nv_handle,
            )
        )

        return ESYS_TR(nv_handle[0])

    def nv_undefine_space(
        self,
        nv_index: ESYS_TR,
        auth_handle: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_UndefineSpace command.

        This function invokes the TPM2_NV_UndefineSpace command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): he NV Index to remove from NV space.
            auth_handle (ESYS_TR): ESYS_TR.OWNER or ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.OWNER.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_UndefineSpace

        TPM Command: TPM2_NV_UndefineSpace
        """

        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_UndefineSpace(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_undefine_space_special(
        self,
        nv_index: ESYS_TR,
        session1: ESYS_TR,
        platform: ESYS_TR = ESYS_TR.PLATFORM,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_UndefineSpaceSpecial command.

        This function invokes the TPM2_NV_UndefineSpaceSpecial command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): Index to be deleted.
            session1 (ESYS_TR): Session handle for authorization of nvIndex (required).
            platform (ESYS_TR): platform ESYS_TR.PLATFORM+{PP}. Defaults to ESYS_TR.PLATFORM.
            session2 (ESYS_TR): Session handle for authorization of platform (optional). Defaults to ESYS_TR.PASSWORD.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_UndefineSpaceSpecial

        TPM Command: TPM2_NV_UndefineSpaceSpecial
        """

        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(platform, "platform", expected=(ESYS_TR.PLATFORM,))
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
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
        """Invoke the TPM2_NV_ReadPublic command.

        This function invokes the TPM2_NV_ReadPublic command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_NV_PUBLIC, TPM2B_NAME] which is the public area of the NV Index and the
            name of the NV Index respectively.

        C Function: Esys_NV_ReadPublic

        TPM Command: TPM2_NV_ReadPublic
        """

        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        nv_public = ffi.new("TPM2B_NV_PUBLIC **")
        nv_name = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_NV_ReadPublic(
                self._ctx, nv_index, session1, session2, session3, nv_public, nv_name
            )
        )
        return (
            TPM2B_NV_PUBLIC(_cdata=_get_dptr(nv_public, lib.Esys_Free)),
            TPM2B_NAME(_cdata=_get_dptr(nv_name, lib.Esys_Free)),
        )

    def nv_write(
        self,
        nv_index: ESYS_TR,
        data: Union[TPM2B_MAX_NV_BUFFER, bytes, str],
        offset: int = 0,
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_Write command.

        This function invokes the TPM2_NV_Write command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index of the area to write.
            data (Union[TPM2B_MAX_NV_BUFFER, bytes, str]): The data to write.
            offset (int): The offset into the NV Area. Defaults to 0.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_Write

        TPM Command: TPM2_NV_Write
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        data_cdata = _get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
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
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_Increment command.

        This function invokes the TPM2_NV_Increment command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to increment.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_Increment

        TPM Command: TPM2_NV_Increment
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_Increment(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_extend(
        self,
        nv_index: ESYS_TR,
        data: Union[TPM2B_MAX_NV_BUFFER, bytes, str],
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_Extend command.

        This function invokes the TPM2_NV_Extend command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to extend.
            data (Union[TPM2B_MAX_NV_BUFFER, bytes, str]): The data to extend.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_Extend

        TPM Command: TPM2_NV_Extend
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        data_cdata = _get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
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
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_SetBits command.

        This function invokes the TPM2_NV_SetBits command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to extend.
            bits (int): The data to OR with the current contents.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_SetBits

        TPM Command: TPM2_NV_SetBits
        """

        if auth_handle is None:
            auth_handle = nv_index

        _check_handle_type(auth_handle, "auth_handle")

        if not isinstance(bits, int):
            raise TypeError(f"Expected bits to be an int, got {type(bits)}")

        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_SetBits(
                self._ctx, auth_handle, nv_index, session1, session2, session3, bits
            )
        )

    def nv_write_lock(
        self,
        nv_index: ESYS_TR,
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_WriteLock command.

        This function invokes the TPM2_NV_WriteLock command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to extend.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_WriteLock

        TPM Command: TPM2_NV_WriteLock
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        _chkrc(
            lib.Esys_NV_WriteLock(
                self._ctx, auth_handle, nv_index, session1, session2, session3
            )
        )

    def nv_global_write_lock(
        self,
        auth_handle: ESYS_TR = ESYS_TR.OWNER,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_GlobalWriteLock command.

        This function invokes the TPM2_NV_GlobalWriteLock command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_GlobalWriteLock

        TPM Command: TPM2_NV_GlobalWriteLock
        """

        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
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
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_MAX_NV_BUFFER:
        """Invoke the TPM2_NV_Read command.

        This function invokes the TPM2_NV_Read command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to be read.
            size (int): Number of octets to read.
            offset (int): Octet offset into the area (optional). Defaults to 0.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_MAX_NV_BUFFER which is the data read.

        C Function: Esys_NV_Read

        TPM Command: TPM2_NV_Read
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(nv_index, "nv_index")

        if not isinstance(size, int):
            raise TypeError(f"Expected size to be an int, got {type(size)}")

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be an int, got {type(offset)}")

        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

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
        return TPM2B_MAX_NV_BUFFER(_get_dptr(data, lib.Esys_Free))

    def nv_read_lock(
        self,
        nv_index: ESYS_TR,
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> None:
        """Invoke the TPM2_NV_ReadLock command.

        This function invokes the TPM2_NV_ReadLock command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): The NV Index to be locked.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization (optional). Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_ReadLock

        TPM Command: TPM2_NV_ReadLock
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
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
        """Invoke the TPM2_NV_ChangeAuth command.

        This function invokes the TPM2_NV_ChangeAuth command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            nv_index (ESYS_TR): Handle of the entity.
            new_auth (Union[TPM2B_DIGEST, bytes, str]): New authorization value.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        C Function: Esys_NV_ChangeAuth

        TPM Command: TPM2_NV_ChangeAuth
        """

        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        new_auth_cdata = _get_cdata(new_auth, TPM2B_DIGEST, "new_auth")
        _chkrc(
            lib.Esys_NV_ChangeAuth(
                self._ctx, nv_index, session1, session2, session3, new_auth_cdata
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
        auth_handle: Optional[ESYS_TR] = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.PASSWORD,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]:
        """Invoke the TPM2_NV_Certify command.

        This function invokes the TPM2_NV_Certify command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            sign_handle (ESYS_TR): Handle of the key used to sign the attestation structure.
            nv_index (ESYS_TR): Index for the area to be certified.
            qualifying_data (Union[TPM2B_DATA, bytes, str]): User-provided qualifying data.
            in_scheme (TPMT_SIG_SCHEME): TPM2_Signing scheme to use if the scheme for signHandle is
                TPM2_ALG.NULL.
            size (int): Number of octets to certify.
            offset (int): Octet offset into the area (optional). Defaults to 0.
            auth_handle (ESYS_TR): Handle indicating the source of the authorization (optional). Defaults to the nv_index.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A Tuple[TPM2B_ATTEST, TPMT_SIGNATURE] which is the structure that was signed and the
            signature over that structure respectively.

        C Function: Esys_NV_Certify

        TPM Command: TPM2_NV_Certify
        """

        if auth_handle is None:
            auth_handle = nv_index
        _check_handle_type(sign_handle, "sign_handle")
        _check_handle_type(auth_handle, "auth_handle")
        _check_handle_type(nv_index, "nv_index")
        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")
        qualifying_data_cdata = _get_cdata(
            qualifying_data, TPM2B_DATA, "qualifying_data"
        )
        in_scheme_cdata = _get_cdata(in_scheme, TPMT_SIG_SCHEME, "in_scheme")

        if not isinstance(size, int):
            raise TypeError(f"Expected size to be of type int, got: {type(size)}")

        if not isinstance(offset, int):
            raise TypeError(f"Expected offset to be of type int, got: {type(offset)}")

        certify_info = ffi.new("TPM2B_ATTEST **")
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
                qualifying_data_cdata,
                in_scheme_cdata,
                size,
                offset,
                certify_info,
                signature,
            )
        )
        return (
            TPM2B_ATTEST(_get_dptr(certify_info, lib.Esys_Free)),
            TPMT_SIGNATURE(_get_dptr(signature, lib.Esys_Free)),
        )

    def vendor_tcg_test(
        self,
        input_data: Union[TPM2B_DATA, bytes, str],
        session1: ESYS_TR = ESYS_TR.NONE,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ) -> TPM2B_DATA:
        """Invoke the TPM2_Vendor_TCG_Test command.

        This function invokes the TPM2_Vendor_TCG_Test command in a one-call
        variant. This means the function will block until the TPM response is
        available.

        Args:
            input_data (Union[TPM2B_DATA, bytes, str]): Dummy data.
            session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
            session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.

        Raises:
            TypeError: If a parameter is not of an expected type.
            ValueError: If a parameter is not of an expected value.
            TSS2_Exception: Any of the various TSS2_RC's the lower layers can return.

        Returns:
            A TPM2B_DATA which is the output dummy data.

        C Function: Esys_Vendor_TCG_Test

        TPM Command: TPM2_Vendor_TCG_Test
        """

        input_data_cdata = _get_cdata(input_data, TPM2B_DATA, "input_data")

        _check_handle_type(session1, "session1")
        _check_handle_type(session2, "session2")
        _check_handle_type(session3, "session3")

        output_data = ffi.new("TPM2B_DATA **")
        _chkrc(
            lib.Esys_Vendor_TCG_Test(
                self._ctx, session1, session2, session3, input_data_cdata, output_data
            )
        )
        return TPM2B_DATA(_get_dptr(output_data, lib.Esys_Free))

    def load_blob(
        self, data: bytes, type_: int = _DEFAULT_LOAD_BLOB_SELECTOR
    ) -> ESYS_TR:
        """load binary ESAPI object as binary blob. Supported are the types :const:`FAPI_ESYSBLOB.CONTEXTLOAD` and :const:`FAPI_ESYSBLOB.DESERIALIZE`.

        Args:
            data (bytes): Binary blob of the ESAPI object to load.
            type_ (int): :const:`FAPI_ESYSBLOB.CONTEXTLOAD` or :const:`FAPI_ESYSBLOB.DESERIALIZE`. Defaults to :const:`FAPI_ESYSBLOB.CONTEXTLOAD`
                if FAPI is installed else :const: `FAPI_ESYSBLOB.DESERIALIZE`.

        Raises:
            ValueError: If type_ is not of an expected value.

        Returns:
            ESYS_TR: The ESAPI handle to the loaded object.
        """
        esys_handle = ffi.new("ESYS_TR *")
        if type_ == FAPI_ESYSBLOB.CONTEXTLOAD:
            offs = ffi.new("size_t *", 0)
            key_ctx = ffi.new("TPMS_CONTEXT *")
            _chkrc(lib.Tss2_MU_TPMS_CONTEXT_Unmarshal(data, len(data), offs, key_ctx))
            _chkrc(lib.Esys_ContextLoad(self._ctx, key_ctx, esys_handle))
        elif type_ == FAPI_ESYSBLOB.DESERIALIZE:
            _chkrc(lib.Esys_TR_Deserialize(self._ctx, data, len(data), esys_handle))
        else:
            raise ValueError(
                f"Expected type_ to be FAPI_ESYSBLOB.CONTEXTLOAD or FAPI_ESYSBLOB.DESERIALIZE, got {type_}"
            )

        return ESYS_TR(esys_handle[0])

    def tr_serialize(self, esys_handle: ESYS_TR) -> bytes:
        """Serialization of an ESYS_TR into a byte buffer.

        Serialize the metadata of an ESYS_TR object into a byte buffer such that it
        can be stored on disk for later use by a different program or context.
        The serialized object can be deserialized using tr_deserialize.

        Args:
            esys_handle (ESYS_TR): The ESYS_TR object to serialize.

        Returns:
            The serialized object as bytes.

        C Function: Esys_TR_Serialize

        Raises:
            TypeError: If esys_handle is not an ESYS_TR.
            TSS2_Exception:
              - TSS2_ESYS_RC_BAD_TR if the ESYS_TR object is unknown to the
                ESYS_CONTEXT.

              - TSS2_ESYS_RC_MEMORY if the buffer for marshaling the object can't
                be allocated.

              - TSS2_ESYS_RC_BAD_VALUE For invalid ESYS data to be marshaled.

              - TSS2_RCs produced by lower layers of the software stack.
        """
        _check_handle_type(esys_handle, "esys_handle")

        buffer_size = ffi.new("size_t *")
        buffer = ffi.new("uint8_t **")
        _chkrc(lib.Esys_TR_Serialize(self._ctx, esys_handle, buffer, buffer_size))
        buffer_size = buffer_size[0]
        buffer = _get_dptr(buffer, lib.Esys_Free)
        return bytes(ffi.buffer(buffer, buffer_size))

    def tr_deserialize(self, buffer: bytes) -> ESYS_TR:
        """Deserialization of an ESYS_TR from a byte buffer.

        Deserialize the metadata of an ESYS_TR object from a byte buffer that was
        stored on disk for later use by a different program or context.
        An object can be serialized using tr_serialize.

        Args:
            buffer (bytes): The ESYS_TR object to deserialize.

        Returns:
            ESYS_TR: The ESAPI handle to the deserialized object.

        C Function: Esys_TR_Deserialize

        Raises:
            TypeError: If a parameter is the incorrect type.

            TSS2_Exception:

               - TSS2_ESYS_RC_MEMORY if the object can not be allocated.

               - TSS2_RCs produced by lower layers of the software stack.
        """

        if not isinstance(buffer, bytes):
            raise TypeError(f"Expected buffer to be of type bytes, got: {type(buffer)}")

        esys_handle = ffi.new("ESYS_TR *")
        _chkrc(lib.Esys_TR_Deserialize(self._ctx, buffer, len(buffer), esys_handle))

        return ESYS_TR(esys_handle[0])

    @staticmethod
    def _fixup_hierarchy(hierarchy: ESYS_TR) -> Union[TPM2_RH, ESYS_TR]:
        """Fixup ESYS_TR values to TPM2_RH constants to work around tpm2-tss API change in 3.0.0.

        In versions tpm2-tss version before 3.0.0 the TPM2_RH constants were used Esys_LoadExternal,
        however the spec and API idioms dictate that an ESYS_TR should be used, and thus that change
        was made. To keep the API constant always expect ESYS_TR's in the Python code and fix them
        up under the hood for old ESAPI versions.

        Args:
            hierarchy (ESYS_TR): The ESYS_TR object to map tp TPM2_RH constant.

        Returns:
          The TPM2_RH.

        Raises:
            - ValueError: If a parameter is the incorrect value.
        """

        if pkgconfig.installed("tss2-esys", "<3.0.0"):
            fixup_map = {
                ESYS_TR.NULL: TPM2_RH.NULL,
                ESYS_TR.OWNER: TPM2_RH.OWNER,
                ESYS_TR.PLATFORM: TPM2_RH.PLATFORM,
                ESYS_TR.ENDORSEMENT: TPM2_RH.ENDORSEMENT,
            }
            if hierarchy not in fixup_map:
                raise RuntimeError(
                    "Expected hierarchy to be one of ESYS_TR.NULL, ESYS_TR.PLATFORM, ESYS_TR.OWNER, ESYS_TR.ENDORSMENT"
                )

            hierarchy = fixup_map[hierarchy]

        return hierarchy
