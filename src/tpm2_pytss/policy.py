# SPDX-License-Identifier: BSD-2
from .internal.utils import _lib_version_atleast, _chkrc

if not _lib_version_atleast("tss2-policy", "4.0.0"):
    raise NotImplementedError("tss2-policy not installed or version is less then 4.0.0")

from .types import (
    TPM2B_DIGEST,
    TPMS_NV_PUBLIC,
    TPM2B_NAME,
    TPMT_PUBLIC,
    TPM2B_NONCE,
    TSS2_OBJECT,
    TSS2_POLICY_PCR_SELECTION,
    TPM2_HANDLE,
)
from .constants import TPM2_ALG, ESYS_TR, TSS2_RC, TPM2_RC
from .TSS2_Exception import TSS2_Exception
from ._libtpm2_pytss import ffi, lib
from .ESAPI import ESAPI
from enum import Enum
from typing import Callable, Union


class policy_cb_types(Enum):
    """Policy callback types"""

    CALC_PCR = 0
    CALC_NAME = 1
    CALC_PUBLIC = 2
    CALC_NVPUBLIC = 3
    EXEC_AUTH = 4
    EXEC_POLSEL = 5
    EXEC_SIGN = 6
    EXEC_POLAUTH = 7
    EXEC_POLAUTHNV = 8
    EXEC_POLDUP = 9
    EXEC_POLACTION = 10


@ffi.def_extern()
def _policy_cb_calc_pcr(selection, out_selection, out_digest, userdata):
    """Callback wrapper for policy PCR calculations

    Args:
        selection (struct TSS2_POLICY_PCR_SELECTION): in
        out_selection (struct TPML_PCR_SELECTION): out
        out_digest (struct TPML_DIGEST): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.CALC_PCR)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        selcopy = ffi.new("TSS2_POLICY_PCR_SELECTION *", selection[0])
        sel = TSS2_POLICY_PCR_SELECTION(_cdata=selcopy)
        cb_selection, cb_digest = cb(sel)
        out_selection.count = cb_selection.count
        for i in range(0, cb_selection.count):
            out_selection.pcrSelections[i] = cb_selection[i]._cdata
        out_digest.count = cb_digest.count
        for i in range(0, cb_digest.count):
            out_digest.digests[i].buffer = cb_digest[i]
            out_digest.digests[i].size = len(cb_digest[i])
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_calc_name(path, name, userdata):
    """Callback wrapper for policy name calculations

    Args:
        path (C string): in
        name (struct TPM2B_DIGEST): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.CALC_NAME)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        pth = ffi.string(path)
        cb_name = cb(pth)
        name.size = len(cb_name)
        name.name = bytes(cb_name.name)
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_calc_public(path, public, userdata):
    """Callback wrapper for getting the public part for a key path

    Args:
        path (C string): in
        public (struct TPMT_PUBLIC): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.CALC_PUBLIC)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        pth = ffi.string(path)
        cb_public = cb(pth)
        public.type = cb_public.type
        public.nameAlg = cb_public.nameAlg
        public.objectAttributes = cb_public.objectAttributes
        public.authPolicy.buffer = bytes(cb_public.authPolicy)
        public.authPolicy.size = cb_public.authPolicy.size
        public.parameters = cb_public.parameters._cdata
        public.unique = cb_public.unique._cdata
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_calc_nvpublic(path, nv_index, nv_public, userdata):
    """Callback wrapper for getting the public part for a NV path

    Args:
        path (C string or NULL): in
        nv_index (TPMI_RH_NV_INDEX or zero): in
        nv_public (struct TPMS_NV_PUBLIC): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.CALC_NVPUBLIC)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        pth = ffi.string(path) if path != ffi.NULL else None
        index = TPM2_HANDLE(nv_index)
        cb_nv_public = cb(pth, index)
        nv_public.nvIndex = cb_nv_public.nvIndex
        nv_public.nameAlg = cb_nv_public.nameAlg
        nv_public.attributes = cb_nv_public.attributes
        nv_public.authPolicy.buffer = bytes(cb_nv_public.authPolicy)
        nv_public.authPolicy.size = cb_nv_public.authPolicy.size
        nv_public.dataSize = cb_nv_public.dataSize
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_auth(name, object_handle, auth_handle, auth_session, userdata):
    """Callback wrapper for getting authorization sessions for a name

    Args:
        name (struct TPM2B_NAME): in
        object_handle (ESYS_TR): out
        auth_handle (ESYS_TR): out
        auth_session (ESYS_TR): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_AUTH)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        nb = ffi.unpack(name.name, name.size)
        name2b = TPM2B_NAME(nb)
        cb_object_handle, cb_auth_handle, cb_auth_session = cb(name2b)
        object_handle[0] = cb_object_handle
        auth_handle[0] = cb_auth_handle
        auth_session[0] = cb_auth_session
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_polsel(
    auth_object, branch_names, branch_count, branch_idx, userdata
):
    """Callback wrapper selection of a policy branch

    Args:
        auth_object (struct TSS2_OBJECT): in
        branch_names (array of C strings): in
        branch_count (int): in
        branch_idx (int): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_POLSEL)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        obj = None
        if auth_object:
            obj = TSS2_OBJECT(handle=auth_object.handle)
        branches = list()
        for i in range(0, branch_count):
            branch = ffi.string(branch_names[i])
            branches.append(branch)
        indx = cb(obj, branches)
        branch_idx[0] = indx
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_sign(
    key_pem,
    public_key_hint,
    key_pem_hash_alg,
    buf,
    buf_size,
    signature,
    signature_size,
    userdata,
):
    """Callback wrapper to signing an operation

    Args:
        key_pem (C string): in
        public_key_hint (C string): in
        key_pem_hash_alg (TPMI_ALG_HASH): in
        buf: (uint8_t array): in
        buf_size (size_t): in
        signature (pointer to uint8_t array): out
        signature_size (pointer to size_t): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_SIGN)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        pem = ffi.string(key_pem)
        key_hint = ffi.string(public_key_hint)
        hash_alg = TPM2_ALG(key_pem_hash_alg)
        b = bytes(ffi.unpack(buf, buf_size))
        cb_signature = cb(pem, key_hint, hash_alg, b)
        signature[0] = ffi.new("char[]", cb_signature)
        signature_size[0] = len(cb_signature)
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_polauth(
    key_public, hash_alg, digest, policy_ref, signature, userdata
):
    """Callback for signing a policy

    Args:
        key_public (struct TPMT_PUBLIC): in
        hash_alg (TPM2_ALG_ID): in
        digest (struct TPM2B_DIGEST): in
        policy_ref (struct TPM2B_NONCE): in
        signature (struct TPMT_SIGNATURE): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_POLAUTH)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        key_pub = TPMT_PUBLIC(_cdata=key_public)
        halg = TPM2_ALG(hash_alg)
        db = ffi.unpack(digest.buffer, digest.size)
        pb = ffi.unpack(policy_ref.buffer, policy_ref.size)
        dig = TPM2B_DIGEST(db)
        polref = TPM2B_NONCE(pb)
        cb_signature = cb(key_pub, halg, dig, polref)
        signature.sigAlg = cb_signature.sigAlg
        signature.signature = cb_signature.signature._cdata
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_polauthnv(nv_public, hash_alg, userdata):
    """Callback wrapper for NV policy authorization

    Args:
        nv_public (struct TPMS_NV_PUBLIC): in
        hash_alg (TPM2_ALG_ID): in
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_POLAUTHNV)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        nvp = TPMS_NV_PUBLIC(nv_public)
        halg = TPM2_ALG(hash_alg)
        cb(nvp, halg)
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_poldup(name, userdata):
    """Callback wrapper to get name for duplication selection

    Args:
        name (struct TPM2B_NAME): out
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_POLDUP)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        cb_name = cb()
        name.size = len(cb_name)
        name.name = bytes(cb_name)
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _policy_cb_exec_polaction(action, userdata):
    """Callback wrapper for policy action

    Args:
        action (C string): in
        userdata (ffi handle): in
    """
    pi = ffi.from_handle(userdata)
    cb = pi._get_callback(policy_cb_types.EXEC_POLACTION)
    if not cb:
        return TSS2_RC.POLICY_RC_NULL_CALLBACK
    try:
        ab = ffi.string(action)
        cb(ab)
    except Exception as e:
        rc = (
            e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.POLICY_RC_GENERAL_FAILURE
        )
        pi._callback_exception = e
        return rc
    return TPM2_RC.SUCCESS


class policy(object):
    """Initialize policy object.

    Args:
        policy (Union(bytes, str]): The JSON policy to calculate or execute.
        hash_alg (TPM2_ALG): The hash algorithm to use for policy calculations.

    Returns:
        An instance of the policy object.

    This class implements the policy part of the TCG TSS 2.0 JSON Data Types
    and Policy Language Specification.

    The specification can be found at https://trustedcomputinggroup.org/resource/tcg-tss-json/
    """

    def __init__(self, policy: Union[bytes, str], hash_alg: TPM2_ALG):
        if isinstance(policy, str):
            policy = policy.encode()
        self._policy = policy
        self._hash_alg = hash_alg
        self._callbacks = dict()
        self._callback_exception = None
        self._ctx_pp = ffi.new("TSS2_POLICY_CTX **")
        _chkrc(lib.Tss2_PolicyInit(policy, hash_alg, self._ctx_pp))
        self._ctx = self._ctx_pp[0]
        self._handle = ffi.new_handle(self)
        self._calc_callbacks = ffi.new("TSS2_POLICY_CALC_CALLBACKS *")
        self._exec_callbacks = ffi.new("TSS2_POLICY_EXEC_CALLBACKS *")

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        """Finalize the policy instance"""
        lib.Tss2_PolicyFinalize(self._ctx_pp)
        self._ctx_pp = ffi.NULL
        self._ctx = ffi.NULL

    @property
    def policy(self) -> bytes:
        """bytes: The JSON policy."""
        return self._policy

    @property
    def hash_alg(self) -> TPM2_ALG:
        """TPM2_ALG: The hash algorithm to be used during policy calculcation."""
        return self._hash_alg

    def _get_callback(self, callback_type: policy_cb_types) -> Callable:
        return self._callbacks.get(callback_type)

    def set_callback(
        self, callback_type: policy_cb_types, callback: Union[None, Callable]
    ):
        """Set callback for policy calculaction or execution

        Args:
            callback_type (policy_cb_types): Which callback to set or unset.
            callback (Union[None, Callable]): The callback function to call, or None to remove the callback.

        Raises:
            ValueError
        """
        userdata = self._handle
        if callback is None:
            userdata = ffi.NULL
        update_calc = False
        update_exec = False
        if callback_type == policy_cb_types.CALC_PCR:
            self._callbacks[callback_type] = callback
            self._calc_callbacks.cbpcr = lib._policy_cb_calc_pcr
            self._calc_callbacks.cbpcr_userdata = userdata
            update_calc = True
        elif callback_type == policy_cb_types.CALC_NAME:
            self._callbacks[callback_type] = callback
            self._calc_callbacks.cbname = lib._policy_cb_calc_name
            self._calc_callbacks.cbname_userdata = userdata
            update_calc = True
        elif callback_type == policy_cb_types.CALC_PUBLIC:
            self._callbacks[callback_type] = callback
            self._calc_callbacks.cbpublic = lib._policy_cb_calc_public
            self._calc_callbacks.cbpublic_userdata = userdata
            update_calc = True
        elif callback_type == policy_cb_types.CALC_NVPUBLIC:
            self._callbacks[callback_type] = callback
            self._calc_callbacks.cbnvpublic = lib._policy_cb_calc_nvpublic
            self._calc_callbacks.cbnvpublic_userdata = userdata
            update_calc = True
        elif callback_type == policy_cb_types.EXEC_AUTH:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbauth = lib._policy_cb_exec_auth
            self._exec_callbacks.cbauth_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_POLSEL:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbpolsel = lib._policy_cb_exec_polsel
            self._exec_callbacks.cbpolsel_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_SIGN:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbsign = lib._policy_cb_exec_sign
            self._exec_callbacks.cbsign_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_POLAUTH:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbauthpol = lib._policy_cb_exec_polauth
            self._exec_callbacks.cbauthpol_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_POLAUTHNV:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbauthnv = lib._policy_cb_exec_polauthnv
            self._exec_callbacks.cbauthnv_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_POLDUP:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbdup = lib._policy_cb_exec_poldup
            self._exec_callbacks.cbdup_userdata = userdata
            update_exec = True
        elif callback_type == policy_cb_types.EXEC_POLACTION:
            self._callbacks[callback_type] = callback
            self._exec_callbacks.cbaction = lib._policy_cb_exec_polaction
            self._exec_callbacks.cbaction_userdata = userdata
            update_exec = True
        else:
            raise ValueError(f"unsupported callback type {callback_type}")

        if update_calc:
            _chkrc(lib.Tss2_PolicySetCalcCallbacks(self._ctx, self._calc_callbacks))
        elif update_exec:
            _chkrc(lib.Tss2_PolicySetExecCallbacks(self._ctx, self._exec_callbacks))

    def execute(self, esys_ctx: ESAPI, session: ESYS_TR):
        """Executes the policy

        Args:
            esys_ctx (ESAPI): The ESAPI instance to use during policy execution.
            session (ESYS_TR): The policy session to use during execution.

        Raises:
            TSS2_Exception or any possible exception from a callback function.
        """
        try:
            _chkrc(lib.Tss2_PolicyExecute(self._ctx, esys_ctx._ctx, session))
        except Exception as e:
            if self._callback_exception is not None:
                raise self._callback_exception
            raise e
        finally:
            self._callback_exception = None

    def calculate(self):
        """Calculate the policy

        Raises:
            TSS2_Exception
        """
        try:
            _chkrc(lib.Tss2_PolicyCalculate(self._ctx))
        except Exception as e:
            if self._callback_exception is not None:
                raise self._callback_exception
            raise e
        finally:
            self._callback_exception = None

    def get_calculated_json(self) -> bytes:
        """Get the calculated policy as JSON

        Returns:
            The calculated JSON policy as bytes

        Raises:
            TSS2_Exception
        """
        size = ffi.new("size_t *", 8096)
        cjson = ffi.new("uint8_t[]", 8096)
        _chkrc(lib.Tss2_PolicyGetCalculatedJSON(self._ctx, cjson, size))
        return ffi.string(cjson, size[0])

    @property
    def description(self) -> bytes:
        """bytes: The policy description."""
        size = ffi.new("size_t *", 8096)
        desc = ffi.new("uint8_t[]", 8096)
        _chkrc(lib.Tss2_PolicyGetDescription(self._ctx, desc, size))
        return ffi.string(desc, size[0])

    def get_calculated_digest(self) -> TPM2B_DIGEST:
        """Get the digest of the calculated policy

        Returns:
            The digest as a TPM2B_DIGEST.

        Raises:
            TSS2_Exception
        """
        dig = ffi.new("TPM2B_DIGEST *")
        _chkrc(lib.Tss2_PolicyGetCalculatedDigest(self._ctx, dig))
        return TPM2B_DIGEST(_cdata=dig[0])
