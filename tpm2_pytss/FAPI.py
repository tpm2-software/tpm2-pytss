"""
SPDX-License-Identifier: BSD-2
"""
import contextlib
import json
import logging
import os
import tempfile
from typing import Any, Callable, List, Optional, Tuple, Union

from ._libtpm2_pytss import lib
from .callbacks import Callback, CallbackType, get_callback, unlock_callback
from .fapi_info import FapiInfo
from .TSS2_Exception import TSS2_Exception
from .types import *
from .utils import _chkrc, to_bytes_or_null

logger = logging.getLogger(__name__)

ffi_malloc = ffi.new_allocator(free=None)

FAPI_CONFIG_ENV = "TSS2_FAPICONF"
FAPI_CONFIG_PATHS = [
    "/etc/tpm2-tss/fapi-config.json",
    "/usr/local/etc/tpm2-tss/fapi-config.json",
]


class FapiConfig(contextlib.ExitStack):
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
            f"Creating FapiConfig: {self.config_tmp_path}:\n{json.dumps(self.config, indent=4)}"
        )

        # Set fapi config env variable
        self.config_env_backup = os.environ.get(FAPI_CONFIG_ENV, None)
        os.environ[FAPI_CONFIG_ENV] = self.config_tmp_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        super().__exit__(exc_type, exc_val, exc_tb)

        if self.config_env_backup is not None:
            os.environ[FAPI_CONFIG_ENV] = self.config_env_backup

        if self.config_tmp_path is not None:
            os.unlink(self.config_tmp_path)


class FAPI:
    """The TPM2 Feature API. This class can be used as a python context or be closed manually via
    :meth:`~tpm2_pytss.FAPI.close`.
    """

    def __init__(self, uri: Optional[Union[bytes, str]] = None):
        self.encoding = "utf-8"

        self.ctx_pp = ffi.new("FAPI_CONTEXT **")
        uri = to_bytes_or_null(uri)
        ret = lib.Fapi_Initialize(self.ctx_pp, uri)
        _chkrc(ret)

        # set callbacks
        self.auth_callback: Optional[Callback] = None
        self.auth_callback_user_data_len = 0

    @property
    def ctx(self):
        """Get the Feature API C context used by the library to hold state.

        Returns:
            The Feature API C context.
        """
        return self.ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        """Finalize the Feature API. This frees allocated memory and invalidates the FAPI object."""
        lib.Fapi_Finalize(self.ctx_pp)

        if self.auth_callback:
            unlock_callback(CallbackType.FAPI_AUTH, self.auth_callback.name)
            self.auth_callback = None
            self.auth_callback_user_data_len = 0

    # TODO flesh out info class
    @property
    def version(self):
        """
        Get the tpm2-tss library version.

        Returns:
            str: The Feature API C context.
        """
        info = json.loads(self.info())
        return FapiInfo(info).version

    @property
    def config(self):  # TODO doc, test
        info = json.loads(self.info())
        return FapiInfo(info).fapi_config

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
        auth_value_eh = to_bytes_or_null(auth_value_eh)
        auth_value_sh = to_bytes_or_null(auth_value_sh)
        auth_value_lockout = to_bytes_or_null(auth_value_lockout, allow_null=False)
        ret = lib.Fapi_Provision(
            self.ctx, auth_value_eh, auth_value_sh, auth_value_lockout
        )
        if ret == lib.TPM2_RC_SUCCESS:
            return True
        if is_provisioned_ok and ret == lib.TSS2_FAPI_RC_ALREADY_PROVISIONED:
            return False
        raise TSS2_Exception(ret)

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
        ret = lib.Fapi_GetRandom(self.ctx, num_bytes, data)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.unpack(data[0], num_bytes)
            lib.Fapi_Free(data[0])
            return bytes(result)
        raise TSS2_Exception(ret)

    def info(self) -> str:  # TODO other type? json?
        """Get Fapi information, containing library info, TPM capabilities and more.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: JSON-encoded info string.
        """
        info = ffi.new("char **")
        ret = lib.Fapi_GetInfo(self.ctx, info)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.string(info[0]).decode(self.encoding)
            lib.Fapi_Free(info[0])
            return result
        raise TSS2_Exception(ret)

    def list(self, search_path: Optional[Union[bytes, str]] = None) -> List[str]:
        """Get a list of all Fapi current object paths.

        Args:
            search_path (bytes or str, optional): If given, only list children of `search_path`. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            List[str]: List of all current Fapi object paths.
        """
        search_path = to_bytes_or_null(search_path, allow_null=False)
        path_list = ffi.new("char **")
        ret = lib.Fapi_List(self.ctx, search_path, path_list)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.string(path_list[0]).decode(self.encoding)
            lib.Fapi_Free(path_list[0])
            return result.split(":")
        raise TSS2_Exception(ret)

    def create_key(
        self,
        path: Union[bytes, str],
        type: Optional[Union[bytes, str]] = None,  # TODO enum
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
        exists_ok: bool = False,
    ) -> bool:
        """Create a cryptographic key inside the TPM.

        Args:
            path (bytes or str): Path to the new key object, e.g. `/HS/SRK/new_signing_key`.
            type (bytes or str, optional): Comma separated list. Possible values: system, sign, decrypt, restricted, exportable, noda, 0x81000000. Defaults to None.
            auth_value (bytes or str, optional): Password to key. Defaults to None.
            exists_ok (bool, optional): Do not throw a TSS2_Exception if an object with the given path already exists. Defaults to False.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if the key was created. False otherwise.
        """
        path = to_bytes_or_null(path)
        type = to_bytes_or_null(type)
        policy_path = to_bytes_or_null(policy_path)
        auth_value = to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateKey(self.ctx, path, type, policy_path, auth_value)
        if ret == lib.TPM2_RC_SUCCESS:
            return True
        if exists_ok and ret == lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS:
            return False
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        padding = to_bytes_or_null(padding)  # enum
        digest = to_bytes_or_null(digest)
        signature = ffi.new("uint8_t **")
        signature_size = ffi.new("size_t *")
        public_key = ffi.new("char **")
        certificate = ffi.new("char **")

        ret = lib.Fapi_Sign(
            self.ctx,
            path,
            padding,
            digest,
            len(digest),
            signature,
            signature_size,
            public_key,
            certificate,
        )
        if ret == lib.TPM2_RC_SUCCESS:
            result = (
                ffi.unpack(ffi.cast("char *", signature[0]), signature_size[0]),
                ffi.string(public_key[0]),
                ffi.string(certificate[0]),
            )
            lib.Fapi_Free(signature[0])
            lib.Fapi_Free(public_key[0])
            lib.Fapi_Free(certificate[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        ret = lib.Fapi_VerifySignature(
            self.ctx, path, digest, len(digest), signature, len(signature)
        )
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        plaintext = to_bytes_or_null(plaintext)
        ciphertext = ffi.new("uint8_t **")
        ciphertext_size = ffi.new("size_t *")
        ret = lib.Fapi_Encrypt(
            self.ctx, path, plaintext, len(plaintext), ciphertext, ciphertext_size
        )
        if ret == lib.TPM2_RC_SUCCESS:
            result = bytes(ffi.unpack(ciphertext[0], ciphertext_size[0]))
            lib.Fapi_Free(ciphertext[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        plaintext = ffi.new("uint8_t **")
        plaintext_size = ffi.new("size_t *")
        ret = lib.Fapi_Decrypt(
            self.ctx, path, ciphertext, len(ciphertext), plaintext, plaintext_size
        )
        if ret == lib.TPM2_RC_SUCCESS:
            result = bytes(ffi.unpack(plaintext[0], plaintext_size[0]))
            lib.Fapi_Free(plaintext[0])
            return result
        raise TSS2_Exception(ret)

    def create_seal(
        self,
        path: Union[bytes, str],
        data: Optional[Union[bytes, str]] = None,
        type: Optional[Union[bytes, str]] = None,
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
        exists_ok: bool = False,
    ) -> bool:
        """Create a Fapi sealed (= encrypted) object, that is data sealed a Fapi parent key. Oftentimes, the data is a digest.

        Args:
            path (bytes or str): The path of the new sealed object.
            data (bytes or str, optional): Data to be sealed (often a digest). If None, random data will be generated. Defaults to None.
            type (bytes or str, optional): Comma separated list. Possible values: system, sign, decrypt, restricted, exportable, noda, 0x81000000. Defaults to None.
            policy_path (bytes or str, optional): The path to the policy which will be associated with the sealed object. Defaults to None.
            auth_value (bytes or str, optional): Password to protect the new sealed object. Defaults to None.
            exists_ok (bool, optional): Do not throw a TSS2_Exception if an object with the given path already exists. Defaults to False.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bool: True if the sealed object was created. False otherwise.
        """
        # TODO if data is none, user should be able to give a size (of the random data)
        path = to_bytes_or_null(path)
        data = to_bytes_or_null(data)
        type = to_bytes_or_null(type)
        policy_path = to_bytes_or_null(policy_path)
        auth_value = to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateSeal(
            self.ctx, path, type, len(data), policy_path, auth_value, data
        )
        if ret == lib.TPM2_RC_SUCCESS:
            return True
        if exists_ok and ret == lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS:
            return False
        raise TSS2_Exception(ret)

    def unseal(self, path: Union[bytes, str]) -> bytes:
        """Unseal a sealed (= encrypted) Fapi object and return the data in plaintext.

        Args:
            path (Union[bytes, str]): The path to the sealed object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The unsealed data in plaintext.
        """
        path = to_bytes_or_null(path)
        data = ffi.new("uint8_t **")
        data_size = ffi.new("size_t *")
        ret = lib.Fapi_Unseal(self.ctx, path, data, data_size)
        if ret == lib.TPM2_RC_SUCCESS:
            result = bytes(ffi.unpack(data[0], data_size[0]))
            lib.Fapi_Free(data[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        import_data = to_bytes_or_null(import_data)
        ret = lib.Fapi_Import(self.ctx, path, import_data)
        if ret == lib.TPM2_RC_SUCCESS:
            return True
        if exists_ok and ret == lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS:
            return False
        raise TSS2_Exception(ret)

    def delete(self, path: Union[bytes, str]) -> None:
        """Delete Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object to delete.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = to_bytes_or_null(path)
        ret = lib.Fapi_Delete(self.ctx, path)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        auth_value = to_bytes_or_null(auth_value)
        ret = lib.Fapi_ChangeAuth(self.ctx, path, auth_value)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        new_path = to_bytes_or_null(new_path)
        exported_data = ffi.new("char **")
        ret = lib.Fapi_ExportKey(self.ctx, path, new_path, exported_data)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.string(exported_data[0]).decode(self.encoding)
            lib.Fapi_Free(exported_data[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        description = to_bytes_or_null(description)
        ret = lib.Fapi_SetDescription(self.ctx, path, description)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def get_description(self, path: Union[bytes, str] = None) -> str:
        """Get the description of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: The description of the Fapi object.
        """
        path = to_bytes_or_null(path)
        description = ffi.new("char **")
        ret = lib.Fapi_GetDescription(self.ctx, path, description)
        if ret == lib.TPM2_RC_SUCCESS:
            # description is guaranteed to be a null-terminated string
            result = ffi.string(description[0]).decode()
            lib.Fapi_Free(description[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        app_data = to_bytes_or_null(app_data)
        app_data_size = len(app_data)
        ret = lib.Fapi_SetAppData(self.ctx, path, app_data, app_data_size)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def get_app_data(self, path: Union[bytes, str]) -> Optional[bytes]:
        """Get the custom application data of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Optional[bytes]: The application data or None.
        """
        path = to_bytes_or_null(path)
        app_data = ffi.new("uint8_t **")
        app_data_size = ffi.new("size_t *")
        ret = lib.Fapi_GetAppData(self.ctx, path, app_data, app_data_size)
        if ret == lib.TPM2_RC_SUCCESS:
            if app_data[0] == ffi.NULL:
                result = None
            else:
                result = bytes(ffi.unpack(app_data[0], app_data_size[0]))
                lib.Fapi_Free(app_data[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        certificate = to_bytes_or_null(certificate)
        ret = lib.Fapi_SetCertificate(self.ctx, path, certificate)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def get_certificate(self, path: Union[bytes, str]) -> str:
        """Get the custom application data of a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            bytes: The application data.
        """
        path = to_bytes_or_null(path)
        certificate = ffi.new("char **")
        ret = lib.Fapi_GetCertificate(self.ctx, path, certificate)
        if ret == lib.TPM2_RC_SUCCESS:
            # certificate is guaranteed to be a null-terminated string
            result = ffi.string(certificate[0]).decode()
            lib.Fapi_Free(certificate[0])
            return result
        raise TSS2_Exception(ret)

    def get_platform_certificates(self, no_cert_ok: bool = False) -> bytes:
        # TODO doc
        # TODO split certificates into list
        # TODO why bytes? is this DER?
        certificate = ffi.new("uint8_t **")
        certificates_size = ffi.new("size_t *")
        ret = lib.Fapi_GetPlatformCertificates(self.ctx, certificate, certificates_size)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.unpack(certificate[0], certificates_size)
            lib.Fapi_Free(certificate[0])
            return result
        if no_cert_ok and ret == lib.TSS2_FAPI_RC_NO_CERT:
            return None
        raise TSS2_Exception(ret)

    def get_tpm_blobs(self, path: Union[bytes, str]) -> Tuple[Any, Any, str]:
        """Get the TPM data blobs and the policy associates with a Fapi object.

        Args:
            path (bytes or str): Path to the Fapi object.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[Any, Any, str]: (tpm_2b_public, tpm_2b_private, policy)
        # TODO cdata types
        """
        path = to_bytes_or_null(path)
        tpm_2b_public = ffi.new("uint8_t **")
        tpm_2b_public_size = ffi.new("size_t *")
        tpm_2b_private = ffi.new("uint8_t **")
        tpm_2b_private_size = ffi.new("size_t *")
        policy = ffi.new("char **")
        ret = lib.Fapi_GetTpmBlobs(
            self.ctx,
            path,
            tpm_2b_public,
            tpm_2b_public_size,
            tpm_2b_private,
            tpm_2b_private_size,
            policy,
        )
        if ret == lib.TPM2_RC_SUCCESS:

            def cleanup():
                # free memory
                lib.Fapi_Free(tpm_2b_public[0])
                lib.Fapi_Free(tpm_2b_private[0])
                lib.Fapi_Free(policy[0])

            policy_str = ffi.string(policy[0]).decode(self.encoding)

            # unmarshal bytes to sapi data types
            offs = ffi.new("size_t *", 0)
            tpm_2b_public_unmarsh = ffi.new("TPM2B_PUBLIC *")
            ret = lib.Tss2_MU_TPM2B_PUBLIC_Unmarshal(
                tpm_2b_public[0], tpm_2b_public_size[0], offs, tpm_2b_public_unmarsh
            )
            if ret != lib.TPM2_RC_SUCCESS:
                cleanup()
                raise TSS2_Exception(ret)
            offs[0] = 0
            tpm_2b_private_unmarsh = ffi.new("TPM2B_PRIVATE *")
            ret = lib.Tss2_MU_TPM2B_PRIVATE_Unmarshal(
                tpm_2b_private[0], tpm_2b_private_size[0], offs, tpm_2b_private_unmarsh
            )
            if ret != lib.TPM2_RC_SUCCESS:
                cleanup()
                raise TSS2_Exception(ret)

            cleanup()

            return (
                tpm_2b_public_unmarsh,
                tpm_2b_private_unmarsh,
                policy_str,
            )
        raise TSS2_Exception(ret)

    def get_esys_blob(self, path):
        """Not implemented yet."""
        raise NotImplementedError()
        # path = to_bytes_or_null(path)
        # type = ffi.new("uint8_t *")
        # data = ffi.new("uint8_t **")
        # length = ffi.new("size_t *")
        # ret = lib.Fapi_GetEsysBlob(self.ctx, path, type, data, length)
        # if ret == lib.TPM2_RC_SUCCESS:
        #
        #     def cleanup():
        #         # free memory
        #         lib.Fapi_Free(data[0])
        #
        #     data_bytes = bytes(ffi.unpack(data[0], length[0]))
        #
        #     esys_ctx = ffi.cast("uint8_t *", esys_ctx)
        #     esys_ctx = ffi.cast(
        #         "ESYS_CONTEXT *", self.ctx + 2
        #     )  # TODO is there a way to get esys ctx from fapi ctx?
        #     bla_l = length[0]  # TODO
        #     bla_d = bytes(ffi.unpack(data[0], length[0]))  # TODO
        #     bla_t = type[0]
        #     bla_s = bytes(ffi.unpack(ffi.cast("uint8_t *", esys_ctx), 16))
        #     esys_handle = ffi.new("ESYS_TR *")
        #     if type[0] == lib.FAPI_ESYSBLOB_CONTEXTLOAD:
        #         offs = ffi.new("size_t *", 0)
        #         key_ctx = ffi.new("TPMS_CONTEXT *")
        #         ret = lib.Tss2_MU_TPMS_CONTEXT_Unmarshal(
        #             data[0], length[0], offs, key_ctx
        #         )
        #         if ret != lib.TPM2_RC_SUCCESS:
        #             cleanup()
        #             raise TSS2_Exception(ret)
        #
        #         ret = lib.Esys_ContextLoad(esys_ctx, key_ctx, esys_handle)
        #         if ret != lib.TPM2_RC_SUCCESS:
        #             cleanup()
        #             raise TSS2_Exception(ret)
        #     elif type[0] == lib.FAPI_ESYSBLOB_DESERIALIZE:
        #         ret = lib.Esys_TR_Deserialize(esys_ctx, data[0], length[0], esys_handle)
        #         if ret != lib.TPM2_RC_SUCCESS:
        #             cleanup()
        #             raise TSS2_Exception(ret)
        #
        #     cleanup()
        #     return esys_handle
        # raise TSS2_Exception(ret)

    def export_policy(self, path: Union[bytes, str]) -> str:
        """Export a policy from the key store as a JSON-encoded string.

        Args:
            path (bytes or str): Path to the FAPI policy.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            str: JSON-encoded policy.
        """
        path = to_bytes_or_null(path)
        policy = ffi.new("char **")
        ret = lib.Fapi_ExportPolicy(self.ctx, path, policy)
        if ret == lib.TPM2_RC_SUCCESS:
            result = ffi.string(policy[0]).decode()
            lib.Fapi_Free(policy[0])
            return result  # TODO parse json?
        raise TSS2_Exception(ret)

    def authorize_policy(
        self,
        policy_path: Union[bytes, str],
        key_path: Union[bytes, str],
        policy_ref: Optional[Union[bytes, str]] = None,
    ):
        """Specifiy the underlying policy/policies for a policy Authorize.

        Args:
            policy_path (bytes or str): Path to the underlying policy.
            key_path (bytes or str): Path to the key associated with the policy Authorize.
            policy_ref (bytes or str, optional): Additional application data (e.g. a reference to another policy). Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        policy_path = to_bytes_or_null(policy_path)
        key_path = to_bytes_or_null(key_path)
        if policy_ref is None:
            policy_ref_len = 0
        else:
            policy_ref_len = len(policy_ref)
        policy_ref = to_bytes_or_null(policy_ref)
        ret = lib.Fapi_AuthorizePolicy(
            self.ctx, policy_path, key_path, policy_ref, policy_ref_len
        )
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        ret = lib.Fapi_PcrRead(self.ctx, index, value, value_size, log)
        if ret == lib.TPM2_RC_SUCCESS:
            result = (
                bytes(ffi.unpack(value[0], value_size[0])),
                ffi.string(log[0]).decode(),
            )
            lib.Fapi_Free(log[0])
            lib.Fapi_Free(value[0])
            return result
        raise TSS2_Exception(ret)

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
        log = to_bytes_or_null(log)
        data = to_bytes_or_null(data)
        ret = lib.Fapi_PcrExtend(self.ctx, index, data, len(data), log)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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

        path = to_bytes_or_null(path)
        quote_type = to_bytes_or_null(quote_type)
        if qualifying_data is None:
            qualifying_data_len = 0
        else:
            qualifying_data_len = len(qualifying_data)
        qualifying_data = to_bytes_or_null(qualifying_data)

        quote_info = ffi.new("char **")
        signature = ffi.new("uint8_t **")
        signature_len = ffi.new("size_t *")
        pcr_log = ffi.new("char **")
        certificate = ffi.new("char **")
        ret = lib.Fapi_Quote(
            self.ctx,
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
        if ret == lib.TPM2_RC_SUCCESS:
            result = (
                ffi.string(quote_info[0]).decode(),
                bytes(ffi.unpack(signature[0], signature_len[0])),
                ffi.string(pcr_log[0]).decode(),
                ffi.string(certificate[0]).decode(),
            )
            lib.Fapi_Free(quote_info[0])
            lib.Fapi_Free(signature[0])
            lib.Fapi_Free(pcr_log[0])
            lib.Fapi_Free(certificate[0])
            return result
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        signature = to_bytes_or_null(signature)
        if qualifying_data is None:
            qualifying_data_len = 0
        else:
            qualifying_data_len = len(qualifying_data)
        qualifying_data = to_bytes_or_null(qualifying_data)
        quote_info = to_bytes_or_null(quote_info)
        pcr_log = to_bytes_or_null(pcr_log)
        ret = lib.Fapi_VerifyQuote(
            self.ctx,
            path,
            qualifying_data,
            qualifying_data_len,
            quote_info,
            signature,
            len(signature),
            pcr_log,
        )
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def create_nv(
        self,
        path: Union[bytes, str],
        size: int,
        type: Optional[Union[bytes, str]] = None,
        policy_path: Optional[Union[bytes, str]] = None,
        auth_value: Optional[Union[bytes, str]] = None,
    ) -> None:
        """Create non-volatile (NV) storage on the TPM.

        Args:
            path (bytes or str): Path to the NV storage area.
            size (int): Size of the storage area in bytes.
            type (bytes or str, optional): Type of the storage area. A combination of `bitfield`, `counter`, `pcr`, `system`, `noda`. Defaults to None.
            policy_path (bytes or str, optional): The path to the policy which will be associated with the storage area. Defaults to None.
            auth_value (bytes or str, optional): Password to protect the new storage area. Defaults to None.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = to_bytes_or_null(path)
        type = to_bytes_or_null(type)
        policy_path = to_bytes_or_null(policy_path)
        auth_value = to_bytes_or_null(auth_value)
        ret = lib.Fapi_CreateNv(self.ctx, path, type, size, policy_path, auth_value)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def nv_read(self, path: Union[bytes, str]) -> Tuple[bytes, str]:
        """Read from non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.

        Returns:
            Tuple[bytes, str]: Data stored in the NV storage area and its associated event log.
        """
        path = to_bytes_or_null(path)
        data = ffi.new("uint8_t **")
        data_size = ffi.new("size_t *")
        log = ffi.new("char **")
        ret = lib.Fapi_NvRead(self.ctx, path, data, data_size, log)
        if ret == lib.TPM2_RC_SUCCESS:
            result = (
                bytes(ffi.unpack(data[0], data_size[0])),
                ffi.string(log[0]).decode(),
            )
            lib.Fapi_Free(data[0])
            lib.Fapi_Free(log[0])
            return result
        raise TSS2_Exception(ret)

    def nv_write(self, path: Union[bytes, str], data: Union[bytes, str]) -> None:
        """Write data to a non-volatile (NV) TPM storage and the associated event log.

        Args:
            path (bytes or str): Path to the NV storage area.
            data (bytes or str): Data to write to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = to_bytes_or_null(path)
        data = to_bytes_or_null(data)
        ret = lib.Fapi_NvWrite(self.ctx, path, data, len(data))
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        path = to_bytes_or_null(path)
        data = to_bytes_or_null(data)
        log = to_bytes_or_null(log)
        ret = lib.Fapi_NvExtend(self.ctx, path, data, len(data), log)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def nv_increment(self, path: Union[bytes, str]) -> None:
        """Increment the counter value stored in non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = to_bytes_or_null(path)
        ret = lib.Fapi_NvIncrement(self.ctx, path)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    def nv_set_bits(self, path: Union[bytes, str], bitmap: int) -> None:
        """Set bits of bitfielad, stored in non-volatile (NV) TPM storage.

        Args:
            path (bytes or str): Path to the NV storage area.
            bitmap (int): Bits to set in the NV storage area.

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """
        path = to_bytes_or_null(path)
        ret = lib.Fapi_NvSetBits(self.ctx, path, bitmap)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

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
        nv_path = to_bytes_or_null(nv_path)
        policy_path = to_bytes_or_null(policy_path)
        ret = lib.Fapi_WriteAuthorizeNv(self.ctx, nv_path, policy_path)
        if ret == lib.TPM2_RC_SUCCESS:
            return
        raise TSS2_Exception(ret)

    # TODO use correct callback signature
    def set_auth_callback(
        self,
        callback: Callable[[str, str, Optional[Any]], bytes],
        user_data: Optional[bytes] = None,
    ) -> None:
        """Register a callback that provides the password for Fapi objects when
        needed. Typically, this callback implements a password prompt.

        Args:
            callback (Callable[[str, str, Optional[Any]], bytes]): A callback function which takes the object path (str), the object description (str) and optionally custom user data (any python object). The callback returns the password (bytes).
            user_data (byte, optional): Bytes that will be handed to the callback. Defaults to None. # TODO size

        Raises:
            TSS2_Exception: If Fapi returned an error code.
        """

        def callback_wrapper(object_path, description, auth, user_data):
            object_path = ffi.string(object_path).decode()
            description = ffi.string(description).decode()
            if user_data == ffi.NULL:
                user_data = None
            else:
                user_data = bytes(
                    ffi.unpack(
                        ffi.cast("uint8_t *", user_data),
                        self.auth_callback_user_data_len,
                    )
                )
            auth_value = callback(object_path, description, user_data)
            # auth value is cleaned up by the FAPI
            auth[0] = ffi_malloc("char[]", auth_value)
            return lib.TPM2_RC_SUCCESS

        if callback is None:
            c_callback = ffi.NULL
            user_data = ffi.NULL

            # unlock c callback
            unlock_callback(CallbackType.FAPI_AUTH, self.auth_callback.name)
            self.auth_callback = None
            self.auth_callback_user_data_len = 0
        else:
            if self.auth_callback is None:
                # get c callback and lock it
                self.auth_callback = get_callback(CallbackType.FAPI_AUTH)

                # link callback wrapper to c function
                callback_wrapper.__name__ = self.auth_callback.name
                ffi.def_extern()(callback_wrapper)

            if user_data is not None:
                self.auth_callback_user_data_len = len(user_data)

            c_callback = self.auth_callback.c_function
            user_data = to_bytes_or_null(user_data)

        ret = lib.Fapi_SetAuthCB(self.ctx, c_callback, user_data)
        if ret != lib.TPM2_RC_SUCCESS:
            raise TSS2_Exception(ret)

    def set_branch_callback(self, callback, user_data):
        """Not implemented yet."""
        raise NotImplementedError()

    def set_sign_callback(self, callback, user_data):
        """Not implemented yet."""
        raise NotImplementedError()

    def set_policy_action_callback(self, callback, user_data):
        """Not implemented yet."""
        raise NotImplementedError()
