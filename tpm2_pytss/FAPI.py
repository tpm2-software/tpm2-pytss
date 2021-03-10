"""
SPDX-License-Identifier: BSD-3
"""
import contextlib
import json
import os
import tempfile
from typing import Any, Callable, List, Optional, Tuple, Union

from ._libtpm2_pytss import lib
from .types import *
from .utils import _chkrc, to_bytes_or_null, TPM2B_pack, TPM2B_unpack
from .TSS2_Exception import TSS2_Exception

FAPI_CONFIG_ENV = "TSS2_FAPICONF"
FAPI_CONFIG_PATH = "/etc/tpm2-tss/fapi-config.json"


class FapiConfig(contextlib.ExitStack):
    """Context to create a temporary Fapi environment."""

    def __init__(self, config: Optional[dict] = None, temp_dirs: bool = True, **kwargs):
        f"""Create a temporary Fapi environment. Get the fapi_conf in this order:
        * `config` if given
        * File specified with environment variable `{FAPI_CONFIG_ENV}` if defined
        * Installed config at `{FAPI_CONFIG_PATH}`

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
            return self

        if self.config is None:
            # Load the currently active fapi-config.json
            config_path = os.environ.get(FAPI_CONFIG_ENV, FAPI_CONFIG_PATH)
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
                    f"Conflicting config entries from temp_dirs and **kwargs: {k}"
                )

            self.config = {**self.config, **temp_dir_config}

        fapi_conf_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.config_tmp_path = fapi_conf_file.name
        fapi_conf_file.write(json.dumps(self.config))
        fapi_conf_file.close
        print(
            f"fapi-config: {self.config_tmp_path}:\n{json.dumps(self.config, indent=4)}"
        )  # TODO Logger

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
    def __init__(self, uri: Optional[Union[bytes, str]] = None):
        self.ctx_pp = ffi.new("FAPI_CONTEXT **")
        uri = to_bytes_or_null(uri)
        ret = lib.Fapi_Initialize(self.ctx_pp, uri)
        _chkrc(ret)

    @property
    def ctx(self):
        return self.ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        lib.Fapi_Finalize(self.ctx_pp)

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
        if ret == 0:  # TODO TPM2_RC_SUCCESS:
            return True
        if (
            is_provisioned_ok and ret == 0x60035
        ):  # TODO TSS2_FAPI_RC_ALREADY_PROVISIONED:
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
        data = ffi.new("uint8_t **")
        ret = lib.Fapi_GetRandom(self.ctx, num_bytes, data)
        if ret == 0:  # TODO TPM2_RC_SUCCESS:
            result = ffi.unpack(data[0], num_bytes)
            lib.Fapi_Free(data[0])
            return bytes(result)
        raise TSS2_Exception(ret)
