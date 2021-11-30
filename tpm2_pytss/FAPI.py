# SPDX-License-Identifier: BSD-2
import pkgconfig

if not pkgconfig.installed("tss2-fapi", ">=3.0.0"):
    raise NotImplementedError("FAPI Not installed or version is not 3.0.0")

import contextlib
import json
import logging
import os
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ._libtpm2_pytss import ffi, lib
from .callbacks import Callback, CallbackType, get_callback, unlock_callback
from .fapi_info import FapiInfo
from .internal.utils import _chkrc, _check_bug_fixed, _get_dptr, _to_bytes_or_null
from .TCTI import TCTI
from .types import TPM2B_PUBLIC, TPM2B_PRIVATE

logger = logging.getLogger(__name__)

ffi_malloc = ffi.new_allocator(free=None)

FAPI_CONFIG_ENV = "TSS2_FAPICONF"
FAPI_CONFIG_PATHS = [
    "/etc/tpm2-tss/fapi-config.json",
    "/usr/local/etc/tpm2-tss/fapi-config.json",
]


class FAPIConfig(contextlib.ExitStack):
    """Context to create a temporary Fapi environment."""

    def __init__(self, config: Optional[dict] = None, temp_dirs: bool = True, **kwargs):
        f"""Create a temporary Fapi environment. Get the fapi_conf in this order:
        * `config` if given
        * File specified with environment variable `{FAPI_CONFIG_ENV}` if defined
        * Installed config at `{FAPI_CONFIG_PATHS}`

        Single entries are overridden if additional named arguments are given
        and/or if `temp_dirs` is True.

        Args:
            config (dict, optional): Fapi configuration to use instead of the installed `fapi-config.json`. Defaults to None.
            temp_dirs (bool, optional): Create temporary keystore and log directories and set the respective config entries. Defaults to True.
            **kwargs: Single configuration entries which override those in `config` or `fapi-config.json`.
        """
        super().__init__()

        self.config_env_backup = None
        self.config_tmp_path = None
        self.config = config

        # Return if no custom fapi config is used
        if not (config is not None or temp_dirs or kwargs):
            return

        if self.config is None:
            # Load the currently active fapi-config.json
            config_path = os.environ.get(FAPI_CONFIG_ENV, None)
            if config_path is None:
                for p in FAPI_CONFIG_PATHS:
                    try:
                        with open(p) as file:
                            self.config = json.load(file)
                            break
                    except FileNotFoundError:
                        # keep trying
                        pass

                if self.config is None:
                    raise RuntimeError(
                        f"Could not find fapi config at {FAPI_CONFIG_PATHS}, "
                        f"set env var {FAPI_CONFIG_ENV}"
                    )
            else:
                with open(config_path) as file:
                    self.config = json.load(file)

        self.config = {**self.config, **kwargs}

        if temp_dirs:
            temp_dir_config = {
                "user_dir": self.enter_context(tempfile.TemporaryDirectory()),
                "system_dir": self.enter_context(tempfile.TemporaryDirectory()),
                "log_dir": self.enter_context(tempfile.TemporaryDirectory()),
            }
            conflicting_keys = [k for k in temp_dir_config.keys() if k in kwargs]
            if conflicting_keys:
                raise ValueError(
                    f"Conflicting config entries from temp_dirs and **kwargs: {conflicting_keys}"
                )

            self.config = {**self.config, **temp_dir_config}

        fapi_conf_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.config_tmp_path = fapi_conf_file.name
        fapi_conf_file.write(json.dumps(self.config))
        fapi_conf_file.close
        logger.debug(
            f"Creating FAPIConfig: {self.config_tmp_path}:\n{json.dumps(self.config, indent=4)}"
        )

        # Set fapi config env variable
        self.config_env_backup = os.environ.get(FAPI_CONFIG_ENV, None)
        os.environ[FAPI_CONFIG_ENV] = self.config_tmp_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        super().__exit__(exc_type, exc_val, exc_tb)

        del os.environ[FAPI_CONFIG_ENV]

        if self.config_tmp_path is not None:
            os.unlink(self.config_tmp_path)


class FAPI:
    """The TPM2 Feature API. This class can be used as a python context or be closed manually via
    :meth:`~tpm2_pytss.FAPI.close`.
    """

    def __init__(self, uri: Optional[Union[bytes, str]] = None):
        self.encoding = "utf-8"

        self._ctx_pp = ffi.new("FAPI_CONTEXT **")
        uri = _to_bytes_or_null(uri)
        ret = lib.Fapi_Initialize(self._ctx_pp, uri)
        _chkrc(ret)

        # set callbacks
        self.callbacks: Dict[CallbackType, Optional[Callback]] = {}

    @property
    def _ctx(self):
        """Get the Feature API C context used by the library to hold state.

        Returns:
            The Feature API C context.
        """
        return self._ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self) -> None:
        """Finalize the Feature API. This frees allocated memory and invalidates the FAPI object."""
        lib.Fapi_Finalize(self._ctx_pp)

        for callback_type, callback in self.callbacks.items():
            if callback is not None:
                unlock_callback(callback_type, callback.name)
                self.callbacks[callback_type] = None

    # TODO flesh out info class
    @property
    def version(self):
        """
        Get the tpm2-tss library version.

        Returns:
            str: The Feature API C context.
        """
        info = json.loads(self.get_info())
        return FapiInfo(info).version

    @property
    def config(self):  # TODO doc, test
        info = json.loads(self.get_info())
        return FapiInfo(info).fapi_config

    @property
    def tcti(self):  # TODO doc, test
        tcti = ffi.new("TSS2_TCTI_CONTEXT **")
        # returns the actual tcti context, not a copy (so no extra memory is allocated by the fapi)
        ret = lib.Fapi_GetTcti(self._ctx, tcti)
        _chkrc(ret)
        return TCTI(tcti[0])

    def provision(
        self,
        auth_value_eh: Optional[Union[bytes, str]] = None,
        auth_value_sh: Optional[Union[bytes, str]] = None,
        auth_value_lockout: Optional[Union[bytes, str]] = None,
        is_provisioned_ok: bool = True,
    ) -> bool:
        """Provision the Feature API. Creates the keystore and creates some TPM
        objects. See also config file `/etc/tpm2-tss/fapi-config.json`.

        Args:
            auth_value_eh (bytes or str, optional): Endorsement Hierarchy password. Defaults to None.
            auth_value_sh (bytes or str, optional, optional): Storage/Owner Hierarchy password. Defaults to None.
            auth_value_lockout (bytes or str, optional): Lockout Hierarchy password. Defaults to None.
            is_provisioned_ok (bool, optional): Do not throw a TSS2_Exception if Fapi is already provisioned. Defaults to True.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if Fapi was provisioned, False otherwise.
        """
        auth_value_eh = _to_bytes_or_null(auth_value_eh)
        auth_value_sh = _to_bytes_or_null(auth_value_sh)
        auth_value_lockout = _to_bytes_or_null(auth_value_lockout, allow_null=False)
        ret = lib.Fapi_Provision(
            self._ctx, auth_value_eh, auth_value_sh, auth_value_lockout
        )
        _chkrc(
            ret,
            acceptable=[lib.TSS2_FAPI_RC_ALREADY_PROVISIONED]
            if is_provisioned_ok
            else None,
        )
        return ret == lib.TPM2_RC_SUCCESS

    def get_random(self, num_bytes: int) -> bytes:
        """Get true random bytes, generated by the TPM.

        Args:
            num_bytes (int): Number of bytes to generate.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The random bytes.
        """
        if num_bytes > 1024:
            logger.warning(
                "Requesting a large number of bytes. This may take a while: {num_bytes}"
            )
        data = ffi.new("uint8_t **")
        ret = lib.Fapi_GetRandom(self._ctx, num_bytes, data)
        _chkrc(ret)
        return bytes(ffi.unpack(_get_dptr(data, lib.Fapi_Free), num_bytes))

    def get_info(self) -> str:
        """Get Fapi information, containing library info, TPM capabilities and more.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: JSON-encoded info string.
        """
        info = ffi.new("char **")
        ret = lib.Fapi_GetInfo(self._ctx, info)
        _chkrc(ret)
        return ffi.string(_get_dptr(info, lib.Fapi_Free)).decode(self.encoding)

    def list(self, search_path: Optional[Union[bytes, str]] = None) -> List[str]:
        """Get a list of all Fapi current object paths.

        Args:
            search_path (bytes or str, optional): If given, only list children of `search_path`. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            List[str]: List of all current Fapi object paths.
        """
        search_path = _to_bytes_or_null(search_path, allow_null=False)
        path_list = ffi.new("char **")
        ret = lib.Fapi_List(self._ctx, search_path, path_list)
        _chkrc(ret)
        return (
            ffi.string(_get_dptr(path_list, lib.Fapi_Free))
            .decode(self.encoding)
            .split(":")
        )

    def create_key(
        self,
        path: Union[bytes, str],
        type_: Optional[Union[bytes, str]] = None,  # TODO enum
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
        exists_ok: bool = False,
    ) -> bool:
        """Create a cryptographic key inside the TPM.

        Args:
            path (bytes or str): Path to the new key object, e.g. `/HS/SRK/new_signing_key`.
            type_ (bytes or str, optional): Comma separated list. Possible values: system, sign, decrypt, restricted, exportable, noda, 0x81000000. Defaults to None.
            auth_value (bytes or str, optional): Password to key. Defaults to None.
            exists_ok (bool, optional): Do not throw a TSS2_Exception if an object with the given path already exists. Defaults to False.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if the key was created. False otherwise.
        """
        path = _to_bytes_or_null(path)
        type_ = _to_bytes_or_null(type_)
        policy_path = _to_bytes_or_null(policy_path)
        auth_value = _to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateKey(self._ctx, path, type_, policy_path, auth_value)
        _chkrc(
            ret, acceptable=lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS if exists_ok else None
        )
        return ret == lib.TPM2_RC_SUCCESS

    def sign(
        self,
        path: Union[bytes, str],
        digest: bytes,
        padding: Optional[Union[bytes, str]] = None,  # TODO enum
    ) -> Tuple[bytes, str, str]:
        """Create a signature over a given digest.

        Args:
            path (bytes or str): Path to the signing key.
            digest (bytes): Digest to sign.
            padding (bytes or str, optional): `"rsa_ssa"` or `"rsa_pss"`. Defaults to None (using the scheme specified in the crypto profile).

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, str, str]: (signature (DER), public key (PEM), certificate (PEM))
        """
        path = _to_bytes_or_null(path)
        padding = _to_bytes_or_null(padding)  # enum
        digest = _to_bytes_or_null(digest)
        signature = ffi.new("uint8_t **")
        signature_size = ffi.new("size_t *")
        public_key = ffi.new("char **")
        certificate = ffi.new("char **")

        ret = lib.Fapi_Sign(
            self._ctx,
            path,
            padding,
            digest,
            len(digest),
            signature,
            signature_size,
            public_key,
            certificate,
        )
        _chkrc(ret)
        return (
            bytes(ffi.unpack(_get_dptr(signature, lib.Fapi_Free), signature_size[0])),
            ffi.string(_get_dptr(public_key, lib.Fapi_Free)),
            ffi.string(_get_dptr(certificate, lib.Fapi_Free)),
        )

    def verify_signature(
        self, path: Union[bytes, str], digest: bytes, signature: bytes
    ):
        """Verify a signature on a given digest.

        Args:
            path (bytes or str): Path to the signing key.
            digest (bytes): Digest which was signed.
            signature (bytes): Signature to be verified.

        Raises:
            TSS2_Exception: If Fapi returned an error code, e.g. if the signature cannot be verified successfully.
        """
        path = _to_bytes_or_null(path)
        ret = lib.Fapi_VerifySignature(
            self._ctx, path, digest, len(digest), signature, len(signature)
        )
        _chkrc(ret)

    def encrypt(
        self, path: Union[bytes, str], plaintext: Union[bytes, str]
    ) -> bytes:  # TODO difference seal/unseal
        """Encrypt the plaintext and return the ciphertext.

        Args:
            path (bytes or str): The decrypt key used for encryption.
            plaintext (bytes or str): The data to be encrypted.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The ciphertext.
        """
        _check_bug_fixed(
            fixed_in="3.2",
            backports=["2.4.7", "3.0.5", "3.1.1"],
            details="Faulty free of FAPI Encrypt might lead to Segmentation Fault. See https://github.com/tpm2-software/tpm2-tss/issues/2092",
        )
        path = _to_bytes_or_null(path)
        plaintext = _to_bytes_or_null(plaintext)
        ciphertext = ffi.new("uint8_t **")
        ciphertext_size = ffi.new("size_t *")
        ret = lib.Fapi_Encrypt(
            self._ctx, path, plaintext, len(plaintext), ciphertext, ciphertext_size
        )
        _chkrc(ret)
        return bytes(
            ffi.unpack(_get_dptr(ciphertext, lib.Fapi_Free), ciphertext_size[0])
        )

    def decrypt(self, path: Union[bytes, str], ciphertext: bytes) -> bytes:
        """Decrypt the ciphertext and return the plaintext.

        Args:
            path (bytes or str): The decrypt key used for decryption.
            ciphertext (bytes or str): The data to be decrypted.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The plaintext.
        """
        path = _to_bytes_or_null(path)
        plaintext = ffi.new("uint8_t **")
        plaintext_size = ffi.new("size_t *")
        ret = lib.Fapi_Decrypt(
            self._ctx, path, ciphertext, len(ciphertext), plaintext, plaintext_size
        )
        _chkrc(ret)
        return bytes(ffi.unpack(plaintext[0], plaintext_size[0]))

    def create_seal(
        self,
        path: Union[bytes, str],
        data: Optional[Union[bytes, str]] = None,
        type_: Optional[Union[bytes, str]] = None,
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
        size: Optional[int] = None,
        exists_ok: bool = False,
    ) -> bool:
        """Create a Fapi sealed (= encrypted) object, that is data sealed a Fapi parent key. Oftentimes, the data is a digest.

        Args:
            path (bytes or str): The path of the new sealed object.
            data (bytes or str, optional): Data to be sealed (often a digest). If None, random data will be generated. Defaults to None.
            type_ (bytes or str, optional): Comma separated list. Possible values: system, sign, decrypt, restricted, exportable, noda, 0x81000000. Defaults to None.
            policy_path (bytes or str, optional): The path to the policy which will be associated with the sealed object. Defaults to None.
            auth_value (bytes or str, optional): Password to protect the new sealed object. Defaults to None.
            size (int, optional): If data is None, random bytes of length size are generated. Parameters data and size cannot be given at the same time. Defaults to None.
            exists_ok (bool, optional): Do not throw a TSS2_Exception if an object with the given path already exists. Defaults to False.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if the sealed object was created. False otherwise.
        """
        path = _to_bytes_or_null(path)
        if data is not None and size is not None:
            raise ValueError("Parameters data and size cannot be given at same time.")
        if data is None and size is None:
            raise ValueError("Either parameter data or parameter size must be given.")
        if data is None:
            data_len = size
        else:
            data_len = len(data)
        data = _to_bytes_or_null(data)
        type_ = _to_bytes_or_null(type_)
        policy_path = _to_bytes_or_null(policy_path)
        auth_value = _to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateSeal(
            self._ctx, path, type_, data_len, policy_path, auth_value, data
        )
        _chkrc(
            ret, acceptable=lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS if exists_ok else None
        )
        return ret == lib.TPM2_RC_SUCCESS

    def unseal(self, path: Union[bytes, str]) -> bytes:
        """Unseal a sealed (= encrypted) Fapi object and return the data in plaintext.

        Args:
            path (Union[bytes, str]): The path to the sealed object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The unsealed data in plaintext.
        """
        path = _to_bytes_or_null(path)
        data = ffi.new("uint8_t **")
        data_size = ffi.new("size_t *")
        ret = lib.Fapi_Unseal(self._ctx, path, data, data_size)
        _chkrc(ret)
        return bytes(ffi.unpack(_get_dptr(data, lib.Fapi_Free), data_size[0]))

    def import_object(
        self,
        path: Union[bytes, str],
        import_data: Union[bytes, str],
        exists_ok: bool = False,
    ) -> bool:
        """Import policy, policy template or key into the keystore.

        Args:
            path (bytes or str): Path of the future Fapi object.
            import_data (bytes or str): JSON-encoded data to import.
            exists_ok (bool, optional): Do not throw a TSS2_Exception if an object with the given path already exists. Defaults to False.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if the object was imported. False otherwise.
        """
        _check_bug_fixed(
            fixed_in="3.2",
            details="FAPI Import will overwrite existing objects with same path silently. See https://github.com/tpm2-software/tpm2-tss/issues/2028",
        )
        path = _to_bytes_or_null(path)
        import_data = _to_bytes_or_null(import_data)
        ret = lib.Fapi_Import(self._ctx, path, import_data)
        _chkrc(
            ret, acceptable=lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS if exists_ok else None
        )
        return ret == lib.TPM2_RC_SUCCESS

    def delete(self, path: Union[bytes, str]) -> None:
        """Delete Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object to delete.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        ret = lib.Fapi_Delete(self._ctx, path)
        _chkrc(ret)

    def change_auth(
        self, path: Union[bytes, str], auth_value: Optional[Union[bytes, str]] = None
    ) -> None:
        """Change the password to a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.
            auth_value (bytes or str, optional): New password. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        auth_value = _to_bytes_or_null(auth_value)
        ret = lib.Fapi_ChangeAuth(self._ctx, path, auth_value)
        _chkrc(ret)

    def export_key(
        self, path: Union[bytes, str], new_path: Union[bytes, str] = None
    ) -> str:
        """Export a Fapi object as a JSON-encoded string.

        Args:
            path (bytes or str): Path to the existing Fapi object.
            new_path (bytes or str, optional): New path to the Fapi object. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: The exported data.
        """
        path = _to_bytes_or_null(path)
        new_path = _to_bytes_or_null(new_path)
        exported_data = ffi.new("char **")
        ret = lib.Fapi_ExportKey(self._ctx, path, new_path, exported_data)
        _chkrc(ret)
        return ffi.string(_get_dptr(exported_data, lib.Fapi_Free)).decode(self.encoding)

    def set_description(
        self, path: Union[bytes, str], description: Optional[Union[bytes, str]] = None
    ) -> None:
        """Set the description of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.
            description (bytes or str, optional): New description of the Fapi object. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        description = _to_bytes_or_null(description)
        ret = lib.Fapi_SetDescription(self._ctx, path, description)
        _chkrc(ret)

    def get_description(self, path: Union[bytes, str] = None) -> str:
        """Get the description of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: The description of the Fapi object.
        """
        path = _to_bytes_or_null(path)
        description = ffi.new("char **")
        ret = lib.Fapi_GetDescription(self._ctx, path, description)
        _chkrc(ret)
        # description is guaranteed to be a null-terminated string
        return ffi.string(_get_dptr(description, lib.Fapi_Free)).decode()

    def set_app_data(
        self, path: Union[bytes, str], app_data: Optional[Union[bytes, str]] = None
    ) -> None:
        """Add custom application data to a Fapi object. This data is saved alongside the object and can be used by the application.

        Args:
            path (bytes or str): Path to the Fapi object.
            app_data (bytes or str, optional): Custom application data to be associated with the Fapi object. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        if app_data is None:
            app_data_len = 0
        else:
            app_data_len = len(app_data)
        app_data = _to_bytes_or_null(app_data)
        ret = lib.Fapi_SetAppData(self._ctx, path, app_data, app_data_len)
        _chkrc(ret)

    def get_app_data(self, path: Union[bytes, str]) -> Optional[bytes]:
        """Get the custom application data of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Optional[bytes]: The application data or None.
        """
        path = _to_bytes_or_null(path)
        app_data = ffi.new("uint8_t **")
        app_data_size = ffi.new("size_t *")
        ret = lib.Fapi_GetAppData(self._ctx, path, app_data, app_data_size)
        _chkrc(ret)
        if app_data[0] == ffi.NULL:
            return None
        return bytes(ffi.unpack(_get_dptr(app_data, lib.Fapi_Free), app_data_size[0]))

    def set_certificate(
        self, path: Union[bytes, str], certificate: Optional[Union[bytes, str]] = None
    ) -> None:
        """Add x509 certificate to a Fapi object. This data is saved alongside the object and can be used by the application.

        Args:
            path (bytes or str): Path to the Fapi object.
            certificate (bytes or str, optional): x509 certificate to be associated with the Fapi object. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        certificate = _to_bytes_or_null(certificate)
        ret = lib.Fapi_SetCertificate(self._ctx, path, certificate)
        _chkrc(ret)

    def get_certificate(self, path: Union[bytes, str]) -> str:
        """Get the custom application data of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The application data.
        """
        path = _to_bytes_or_null(path)
        certificate = ffi.new("char **")
        ret = lib.Fapi_GetCertificate(self._ctx, path, certificate)
        _chkrc(ret)
        # certificate is guaranteed to be a null-terminated string
        return ffi.string(_get_dptr(certificate, lib.Fapi_Free)).decode()

    def get_platform_certificates(self, no_cert_ok: bool = False) -> bytes:
        """Get the platform certificate and the so-called delta certificates.

        Args:
            no_cert_ok (bool, optional): If True, an empty byte string is returned if no certificate is found. If False, in this case a TSS2_Exception is raised. Defaults to False.

        Raises:
            TSS2_Exception:  If Fapi returned an error code.

        Returns:
            bytes: The platform certificates
        """
        _check_bug_fixed(
            fixed_in="3.2",
            backports=["2.4.7", "3.0.5", "3.1.1"],
            details="FAPI Get Platform Certificate might lead wrong sequence errors. See https://github.com/tpm2-software/tpm2-tss/issues/2091",
        )

        # TODO split certificates into list
        # TODO why bytes? is this DER?
        certificate = ffi.new("uint8_t **")
        certificates_size = ffi.new("size_t *")
        ret = lib.Fapi_GetPlatformCertificates(
            self._ctx, certificate, certificates_size
        )
        _chkrc(ret, acceptable=lib.TSS2_FAPI_RC_NO_CERT if no_cert_ok else None)
        if no_cert_ok and ret == lib.TSS2_FAPI_RC_NO_CERT:
            return b""
        return bytes(
            ffi.unpack(_get_dptr(certificate, lib.Fapi_Free), certificates_size)
        )

    def get_tpm_blobs(
        self, path: Union[bytes, str]
    ) -> Tuple[TPM2B_PUBLIC, TPM2B_PRIVATE, str]:
        """Get the TPM data blobs and the policy associates with a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[TPM2B_PUBLIC, TPM2B_PRIVATE, str]: (tpm_2b_public, tpm_2b_private, policy)
        """
        path = _to_bytes_or_null(path)
        tpm_2b_public = ffi.new("uint8_t **")
        tpm_2b_public_size = ffi.new("size_t *")
        tpm_2b_private = ffi.new("uint8_t **")
        tpm_2b_private_size = ffi.new("size_t *")
        policy = ffi.new("char **")
        ret = lib.Fapi_GetTpmBlobs(
            self._ctx,
            path,
            tpm_2b_public,
            tpm_2b_public_size,
            tpm_2b_private,
            tpm_2b_private_size,
            policy,
        )
        _chkrc(ret)

        policy_str = ffi.string(policy[0]).decode(self.encoding)

        tpm_2b_public_buffer = bytes(
            ffi.buffer(tpm_2b_public[0], tpm_2b_public_size[0])
        )
        tpm_2b_public_unmarsh, _ = TPM2B_PUBLIC.unmarshal(tpm_2b_public_buffer)

        tpm_2b_private_buffer = bytes(
            ffi.buffer(tpm_2b_private[0], tpm_2b_private_size[0])
        )
        tpm_2b_private_unmarsh, _ = TPM2B_PRIVATE.unmarshal(tpm_2b_private_buffer)

        return (
            tpm_2b_public_unmarsh,
            tpm_2b_private_unmarsh,
            policy_str,
        )

    def get_esys_blob(self, path: Union[bytes, str]) -> Tuple[bytes, Any]:
        """Return the ESAPI binary blob associated with a Fapi object.

        This blob can be easily loaded with :meth:`~tpm2_pytss.ESAPI.load_blob()`.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, Any]: A tuple of the binary blob and its type (:const:`FAPI_ESYSBLOB.CONTEXTLOAD` or :const:`FAPI_ESYSBLOB.DESERIALIZE)`
        """
        path = _to_bytes_or_null(path)
        type_ = ffi.new("uint8_t *")
        data = ffi.new("uint8_t **")
        length = ffi.new("size_t *")
        ret = lib.Fapi_GetEsysBlob(self._ctx, path, type_, data, length)
        _chkrc(ret)
        return bytes(ffi.unpack(_get_dptr(data, lib.Fapi_Free), length[0])), type_[0]

    def export_policy(self, path: Union[bytes, str]) -> str:
        """Export a policy from the key store as a JSON-encoded string.

        Args:
            path (bytes or str): Path to the FAPI policy.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: JSON-encoded policy.
        """
        path = _to_bytes_or_null(path)
        policy = ffi.new("char **")
        ret = lib.Fapi_ExportPolicy(self._ctx, path, policy)
        _chkrc(ret)
        return ffi.string(_get_dptr(policy, lib.Fapi_Free)).decode()

    def authorize_policy(
        self,
        policy_path: Union[bytes, str],
        key_path: Union[bytes, str],
        policy_ref: Optional[Union[bytes, str]] = None,
    ):
        """Specify the underlying policy/policies for a policy Authorize.

        Args:
            policy_path (bytes or str): Path to the underlying policy.
            key_path (bytes or str): Path to the key associated with the policy Authorize.
            policy_ref (bytes or str, optional): Additional application data (e.g. a reference to another policy). Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        policy_path = _to_bytes_or_null(policy_path)
        key_path = _to_bytes_or_null(key_path)
        if policy_ref is None:
            policy_ref_len = 0
        else:
            policy_ref_len = len(policy_ref)
        policy_ref = _to_bytes_or_null(policy_ref)
        ret = lib.Fapi_AuthorizePolicy(
            self._ctx, policy_path, key_path, policy_ref, policy_ref_len
        )
        _chkrc(ret)

    def pcr_read(self, index: int) -> Tuple[bytes, str]:
        """Read the value of a TPM Platform Configuration Register (PCR) and its
        associated event log.

        Args:
            index (int): Index of the PCR (in the range of 0-23 in most cases).

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, str]: (pcr_value, event_log)
        """
        value = ffi.new("uint8_t **")
        value_size = ffi.new("size_t *")
        log = ffi.new("char **")
        ret = lib.Fapi_PcrRead(self._ctx, index, value, value_size, log)
        _chkrc(ret)
        return (
            bytes(ffi.unpack(_get_dptr(value, lib.Fapi_Free), value_size[0])),
            ffi.string(_get_dptr(log, lib.Fapi_Free)).decode(),
        )

    def pcr_extend(
        self,
        index: int,
        data: Union[bytes, str],
        log: Optional[Union[bytes, str]] = None,
    ) -> None:
        """Extend the value of a TPM Platform Configuration Register (PCR).
        The data given by the user and the previous PCR value are hashed
        together. The resulting digest is stored as the new PCR value. As a
        result, a PCR value depends on every piece of data given via the extend
        command (until the PCR is reset).

        Args:
            index (int): Index of the PCR (in the range of 0-23 in most cases).
            data (bytes or str): Input data to the extend operation.
            log (bytes or str, optional): JSON-encoded event log data. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, str]: PCR value and its associated event log.
        """
        # TODO "extend", formula in doc
        log = _to_bytes_or_null(log)
        data = _to_bytes_or_null(data)
        ret = lib.Fapi_PcrExtend(self._ctx, index, data, len(data), log)
        _chkrc(ret)

    def quote(
        self,
        path: Union[bytes, str],
        pcrs: List[int],
        quote_type: Optional[Union[bytes, str]] = None,
        qualifying_data: Optional[Union[bytes, str]] = None,
    ) -> Tuple[str, bytes, str, str]:
        """Create a TPM quote, that is a signed data structure of the TPM Platform Configuration Registers (PCRs), reset count, firmware version and more.

        Args:
            path (bytes or str): Path to the key used for signing.
            pcrs (List[int]): List of PCR indices to be included in the quote.
            quote_type (bytes or str, optional): Type of quote to create. The default "TPM-Quote" is used if None is given. Defaults to None.
            qualifying_data (bytes or str, optional): Additional application-defined data. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[str, bytes, str, str]: info, signature, pcr_log, certificate
        """
        _check_bug_fixed(
            fixed_in="3.2",
            backports=["2.4.7", "3.0.5", "3.1.1"],
            details="Multiple calls of FAPI Quote might lead to TPM out of memory errors. See https://github.com/tpm2-software/tpm2-tss/issues/2084",
        )

        path = _to_bytes_or_null(path)
        quote_type = _to_bytes_or_null(quote_type)
        if qualifying_data is None:
            qualifying_data_len = 0
        else:
            qualifying_data_len = len(qualifying_data)
        qualifying_data = _to_bytes_or_null(qualifying_data)

        quote_info = ffi.new("char **")
        signature = ffi.new("uint8_t **")
        signature_len = ffi.new("size_t *")
        pcr_log = ffi.new("char **")
        certificate = ffi.new("char **")
        ret = lib.Fapi_Quote(
            self._ctx,
            pcrs,
            len(pcrs),
            path,
            quote_type,
            qualifying_data,
            qualifying_data_len,
            quote_info,
            signature,
            signature_len,
            pcr_log,
            certificate,
        )
        _chkrc(ret)
        return (
            ffi.string(_get_dptr(quote_info, lib.Fapi_Free)).decode(),
            bytes(ffi.unpack(_get_dptr(signature, lib.Fapi_Free), signature_len[0])),
            ffi.string(_get_dptr(pcr_log, lib.Fapi_Free)).decode(),
            ffi.string(
                _get_dptr(certificate, lib.Fapi_Free) or ffi.new("char *")
            ).decode(),
        )

    def verify_quote(
        self,
        path: Union[bytes, str],
        signature: bytes,
        quote_info: Union[bytes, str],
        qualifying_data: Optional[Union[bytes, str]] = None,
        pcr_log: Optional[Union[bytes, str]] = None,
    ):
        """Verify the signature to a TPM quote.

        Args:
            path (bytes or str): Path to the key used for verifying the signature.
            signature (bytes): Signature to the quote.
            quote_info (bytes or str, optional): Quote info structure.
            qualifying_data (bytes or str, optional): Additional application-defined data. Defaults to None.
            pcr_log (bytes or str, optional): JSON-encoded PCR log entry.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        signature = _to_bytes_or_null(signature)
        if qualifying_data is None:
            qualifying_data_len = 0
        else:
            qualifying_data_len = len(qualifying_data)
        qualifying_data = _to_bytes_or_null(qualifying_data)
        quote_info = _to_bytes_or_null(quote_info)
        pcr_log = _to_bytes_or_null(pcr_log)
        ret = lib.Fapi_VerifyQuote(
            self._ctx,
            path,
            qualifying_data,
            qualifying_data_len,
            quote_info,
            signature,
            len(signature),
            pcr_log,
        )
        _chkrc(ret)

    def create_nv(
        self,
        path: Union[bytes, str],
        size: int,
        type_: Optional[Union[bytes, str]] = None,
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
    ) -> None:
        """Create non-volatile (NV) storage on the TPM.

        Args:
            path (bytes or str): Path to the NV storage area.
            size (int): Size of the storage area in bytes.
            type_ (bytes or str, optional): Type of the storage area. A combination of `bitfield`, `counter`, `pcr`, `system`, `noda`. Defaults to None.
            policy_path (bytes or str, optional): The path to the policy which will be associated with the storage area. Defaults to None.
            auth_value (bytes or str, optional): Password to protect the new storage area. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        type_ = _to_bytes_or_null(type_)
        policy_path = _to_bytes_or_null(policy_path)
        auth_value = _to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateNv(self._ctx, path, type_, size, policy_path, auth_value)
        _chkrc(ret)

    def nv_read(self, path: Union[bytes, str]) -> Tuple[bytes, str]:
        """Read from non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, str]: Data stored in the NV storage area and its associated event log.
        """
        path = _to_bytes_or_null(path)
        data = ffi.new("uint8_t **")
        data_size = ffi.new("size_t *")
        log = ffi.new("char **")
        ret = lib.Fapi_NvRead(self._ctx, path, data, data_size, log)
        _chkrc(ret)
        return (
            bytes(ffi.unpack(_get_dptr(data, lib.Fapi_Free), data_size[0])),
            ffi.string(_get_dptr(log, lib.Fapi_Free)).decode(),
        )

    def nv_write(self, path: Union[bytes, str], data: Union[bytes, str]) -> None:
        """Write data to a non-volatile (NV) TPM storage and the associated event log.

        Args:
            path (bytes or str): Path to the NV storage area.
            data (bytes or str): Data to write to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        data = _to_bytes_or_null(data)
        ret = lib.Fapi_NvWrite(self._ctx, path, data, len(data))
        _chkrc(ret)

    def nv_extend(
        self,
        path: Union[bytes, str],
        data: Union[bytes, str],
        log: Optional[Union[bytes, str]] = None,
    ) -> None:
        """Perform an extend operation on a non-volatile TPM storage area.
        Requires an NV object of type `pcr`. For more information on the extend
        operation, see :meth:`~tpm2_pytss.FAPI.pcr_extend`.

        Args:
            path (bytes or str): Path to the NV storage area.
            data (bytes or str): Input data to the extend operation.
            log (bytes or str, optional): JSON-encoded event to be associated with this change. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        data = _to_bytes_or_null(data)
        log = _to_bytes_or_null(log)
        ret = lib.Fapi_NvExtend(self._ctx, path, data, len(data), log)
        _chkrc(ret)

    def nv_increment(self, path: Union[bytes, str]) -> None:
        """Increment the counter value stored in non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        ret = lib.Fapi_NvIncrement(self._ctx, path)
        _chkrc(ret)

    def nv_set_bits(self, path: Union[bytes, str], bitmap: int) -> None:
        """Set bits of bitfielad, stored in non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.
            bitmap (int): Bits to set in the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = _to_bytes_or_null(path)
        ret = lib.Fapi_NvSetBits(self._ctx, path, bitmap)
        _chkrc(ret)

    def write_authorize_nv(
        self, nv_path: Union[bytes, str], policy_path: Union[bytes, str]
    ) -> None:
        """Write a policy to non-volatile (NV) TPM storage.

        Args:
            nv_path (bytes or str): Path to the NV storage area.
            policy_path (bytes or str): Path to the policy to be written.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        nv_path = _to_bytes_or_null(nv_path)
        policy_path = _to_bytes_or_null(policy_path)
        ret = lib.Fapi_WriteAuthorizeNv(self._ctx, nv_path, policy_path)
        _chkrc(ret)

    def _register_callback(
        self,
        callback_type: CallbackType,
        callback_wrapper: Callable,
        unlock: bool = False,
    ) -> Callable:
        """(Un)register a C callback and tie it to a python wrapper. Does not call Fapi API calls.

        Args:
            callback_type (CallbackType): Type of callback. Each type can have up to one callback.
            callback_wrapper (Callable): Python wrapper which is called by the C callback and will call a user-defined function.
            unlock (bool, optional): True if the callback is to be freed again. Defaults to False.

        Returns:
            str: CFFI binding function
        """
        if unlock and self.callbacks[callback_type] is not None:
            # unlock c callback
            unlock_callback(CallbackType.FAPI_AUTH, self.callbacks[callback_type].name)  # type: ignore
            self.callbacks[callback_type] = None

            c_callback = ffi.NULL
        else:
            if (
                callback_type not in self.callbacks
                or self.callbacks[callback_type] is None
            ):
                # get c callback and lock it
                self.callbacks[callback_type] = get_callback(callback_type)

            # link callback wrapper to c function
            callback_wrapper.__name__ = self.callbacks[callback_type].name  # type: ignore
            ffi.def_extern()(callback_wrapper)

            c_callback = self.callbacks[callback_type].c_function  # type: ignore

        return c_callback

    def set_auth_callback(
        self,
        callback: Optional[Callable[[str, str, Optional[bytes]], bytes]] = None,
        user_data: Optional[Union[bytes, str]] = None,
    ) -> None:
        """Register a callback that provides the password for Fapi objects when
        needed. Typically, this callback implements a password prompt. If `callback` is None, the callback function is reset.

        Args:
            callback (Callable[[str, str, Optional[bytes]], bytes], optional): A callback function `callback(path, description, user_data=None)` which returns the password (:class:`bytes`). Defaults to None.
            user_data (byte, optional): Bytes that will be handed to the callback. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        if callback is None and user_data is not None:
            raise RuntimeError("If callback is None, user_data must be None, too.")

        if user_data is None:
            user_data_len = 0
        else:
            user_data_len = len(user_data)
        user_data = _to_bytes_or_null(user_data)

        def callback_wrapper(path, description, auth, user_data):
            path = ffi.string(path).decode()
            description = ffi.string(description).decode()
            if user_data == ffi.NULL:
                user_data = None
            else:
                user_data = bytes(
                    ffi.unpack(ffi.cast("uint8_t *", user_data), user_data_len)
                )
            try:
                auth_value = callback(path, description, user_data)
            except Exception:
                return lib.TSS2_FAPI_RC_CB_FAILURE

            # auth value is cleaned up by the FAPI
            auth[0] = ffi_malloc("char[]", auth_value)
            return lib.TPM2_RC_SUCCESS

        c_callback = self._register_callback(
            CallbackType.FAPI_AUTH, callback_wrapper, unlock=callback is None
        )

        ret = lib.Fapi_SetAuthCB(self._ctx, c_callback, user_data)
        _chkrc(ret)

    def set_branch_callback(
        self,
        callback: Optional[
            Callable[[str, str, List[str], Optional[bytes]], int]
        ] = None,
        user_data: Optional[Union[bytes, str]] = None,
    ):
        """Set the Fapi policy branch callback, called to decide which policy path to take in a policy Or. If `callback` is None, the callback function is reset.

        Args:
            callback (Callable[[str, str, List[str], Optional[bytes]], int], optional): A callback function `callback(path, description, branch_names, user_data=None)` which returns the index (:class:`int`) of the selected branch in `branch_names`. Defaults to None.
            user_data (bytes or str, optional): Custom data passed to the callback function. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """

        if callback is None and user_data is not None:
            raise ValueError("If callback is None, user_data must be None, too.")

        if user_data is None:
            user_data_len = 0
        else:
            user_data_len = len(user_data)
        user_data = _to_bytes_or_null(user_data)

        def callback_wrapper(
            path, description, branch_names, num_branches, selected_branch, user_data
        ):
            path = ffi.string(path).decode()
            description = ffi.string(description).decode()
            branch_names = [
                ffi.string(branch_names[i]).decode() for i in range(0, num_branches)
            ]
            if user_data == ffi.NULL:
                user_data = None
            else:
                user_data = bytes(
                    ffi.unpack(ffi.cast("uint8_t *", user_data), user_data_len)
                )
            try:
                selected_branch[0] = callback(
                    path, description, branch_names, user_data
                )
            except Exception:
                return lib.TSS2_FAPI_RC_GENERAL_FAILURE
            return lib.TPM2_RC_SUCCESS

        c_callback = self._register_callback(
            CallbackType.FAPI_BRANCH, callback_wrapper, unlock=callback is None
        )
        ret = lib.Fapi_SetBranchCB(self._ctx, c_callback, user_data)
        _chkrc(ret)

    def set_sign_callback(
        self,
        callback: Optional[
            Callable[[str, str, str, str, int, bytes, Optional[bytes]], bytes]
        ] = None,
        user_data: Optional[Union[bytes, str]] = None,
    ):
        """Set the Fapi signing callback which is called to satisfy the policy Signed. If `callback` is None, the callback function is reset.

        Args:
            callback (Callable[[str, str, str, str, int, bytes, Optional[bytes]], bytes], optional): A callback function `callback(path, description, public_key, public_key_hint, hash_alg, data_to_sign, user_data=None)` which returns a signature (:class:`bytes`) of `data_to_sign`. Defaults to None.
            user_data (bytes or str, optional): Custom data passed to the callback function. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        _check_bug_fixed(
            fixed_in="3.2",
            details="FAPI PolicySigned default nameAlg might be SHA1 unexpectedly. See https://github.com/tpm2-software/tpm2-tss/issues/2080. Fixed in https://github.com/tpm2-software/tpm2-tss/commit/b843960b6e601a786b469832392dc0a12e13cf34",
        )

        if callback is None and user_data is not None:
            raise RuntimeError("If callback is None, user_data must be None, too.")

        if user_data is None:
            user_data_len = 0
        else:
            user_data_len = len(user_data)
        user_data = _to_bytes_or_null(user_data)

        def callback_wrapper(
            path,
            description,
            public_key,
            public_key_hint,
            hash_alg,
            data_to_sign,
            data_to_sign_len,
            signature,
            signature_len,
            user_data,
        ):
            path = ffi.string(path).decode()
            description = ffi.string(description).decode()
            public_key = ffi.string(public_key).decode()
            public_key_hint = ffi.string(public_key_hint).decode()
            data_to_sign = bytes(ffi.unpack(data_to_sign, data_to_sign_len))
            if user_data == ffi.NULL:
                user_data = None
            else:
                user_data = bytes(
                    ffi.unpack(ffi.cast("uint8_t *", user_data), user_data_len,)
                )
            try:
                signature_value = callback(
                    path,
                    description,
                    public_key,
                    public_key_hint,
                    hash_alg,
                    data_to_sign,
                    user_data,
                )
            except Exception:
                return lib.TSS2_FAPI_RC_CB_FAILURE

            # signature is cleaned up by the FAPI
            signature[0] = ffi_malloc("char[]", signature_value)
            signature_len[0] = len(signature_value)
            return lib.TPM2_RC_SUCCESS

        c_callback = self._register_callback(
            CallbackType.FAPI_SIGN, callback_wrapper, unlock=callback is None
        )
        ret = lib.Fapi_SetSignCB(self._ctx, c_callback, user_data)
        _chkrc(ret)

    def set_policy_action_callback(
        self,
        callback: Optional[Callable[[str, str, Optional[bytes]], None]] = None,
        user_data: Optional[Union[bytes, str]] = None,
    ):
        """Set the policy Action callback which is called to satisfy the policy Action. If `callback` is None, the callback function is reset.

        Args:
            callback (Callable[[str, str, Optional[bytes]], None], optional): A callback function `callback(path, action, user_data=None)`. Defaults to None.
            user_data (bytes or str, optional): Custom data passed to the callback function. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        if callback is None and user_data is not None:
            raise ValueError("If callback is None, user_data must be None, too.")

        _check_bug_fixed(
            fixed_in="3.2",
            backports=["2.4.7", "3.0.5", "3.1.1"],
            details="FAPI Policy Action might lead to crashes. See https://github.com/tpm2-software/tpm2-tss/issues/2089",
        )

        if user_data is None:
            user_data_len = 0
        else:
            user_data_len = len(user_data)
        user_data = _to_bytes_or_null(user_data)

        def callback_wrapper(path, action, user_data):
            path = ffi.string(path).decode()
            action = ffi.string(action).decode()
            if user_data == ffi.NULL:
                user_data = None
            else:
                user_data = bytes(
                    ffi.unpack(ffi.cast("uint8_t *", user_data), user_data_len)
                )
            try:
                callback(path, action, user_data)
            except Exception:
                return lib.TSS2_FAPI_RC_GENERAL_FAILURE
            return lib.TPM2_RC_SUCCESS

        c_callback = self._register_callback(
            CallbackType.FAPI_POLICYACTION, callback_wrapper, unlock=callback is None
        )
        ret = lib.Fapi_SetPolicyActionCB(self._ctx, c_callback, user_data)
        _chkrc(ret)
