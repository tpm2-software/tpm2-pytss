# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
import os
import json
import pathlib
import logging
import tempfile
import contextlib
from functools import partial, wraps
from typing import Optional, ByteString, NamedTuple

from .util.swig import Wrapper
from .util.retry import retry_tcti_loop, retry_tcti_catch
from .binding import (
    AuthSessionContext,
    FAPIBinding,
    FlushTRContext,
    NVContext,
    TPML_PCR_SELECTION_PTR,
    TPMT_HA_PTR,
)
from .context import BaseContextMetaClass
from .config import SYSCONFDIR

# Read default values from system wide default FAPI config
DEFAULT_FAPI_CONFIG_PATH = pathlib.Path(SYSCONFDIR, "tpm2-tss", "fapi-config.json")
DEFAULT_FAPI_CONFIG_CONTENTS = DEFAULT_FAPI_CONFIG_PATH.read_text()
DEFAULT_FAPI_CONFIG = json.loads(DEFAULT_FAPI_CONFIG_CONTENTS)


# Environment variable containing FAPI config
ENV_FAPI_CONFIG = "TSS2_FAPICONF"


FAPIConfig = NamedTuple(
    "FAPIConfig",
    [
        ("profile_dir", str),
        ("user_dir", str),
        ("system_dir", str),
        ("log_dir", str),
        ("profile_name", str),
        ("tcti", str),
        ("system_pcrs", TPML_PCR_SELECTION_PTR),
        ("ek_cert_file", str),
        ("ek_cert_less", bool),
        ("ek_fingerprint", TPMT_HA_PTR),
        ("tcti_retry", int),
    ],
)


def export(self):
    exported = self._asdict()
    remove = [key for key, value in exported.items() if value is None]
    for key in remove:
        del exported[key]
    return exported


@classmethod
def default(cls, **kwargs):
    return cls(
        profile_dir=DEFAULT_FAPI_CONFIG.get("profile_dir", None),
        user_dir=DEFAULT_FAPI_CONFIG.get("user_dir", None),
        system_dir=DEFAULT_FAPI_CONFIG.get("system_dir", None),
        log_dir=DEFAULT_FAPI_CONFIG.get("log_dir", None),
        profile_name=DEFAULT_FAPI_CONFIG.get("profile_name", None),
        tcti=DEFAULT_FAPI_CONFIG.get("tcti", None),
        system_pcrs=DEFAULT_FAPI_CONFIG.get("system_pcrs", None),
        ek_cert_file=DEFAULT_FAPI_CONFIG.get("ek_cert_file", None),
        ek_cert_less=DEFAULT_FAPI_CONFIG.get("ek_cert_less", None),
        ek_fingerprint=DEFAULT_FAPI_CONFIG.get("ek_fingerprint", None),
        tcti_retry=1,
    )


FAPIConfig.export = export
FAPIConfig.default = default
FAPIDefaultConfig = FAPIConfig.default()


class InvalidArgumentError(Exception):
    pass  # pragma: no cov


@contextlib.contextmanager
def temp_fapi_config(config):
    if config is None:
        yield
        return
    with tempfile.NamedTemporaryFile(mode="w") as fileobj:
        old_fapi_config = os.environ.get(ENV_FAPI_CONFIG, None)
        try:
            exported = config.export()
            del exported["tcti_retry"]
            json.dump(exported, fileobj)
            fileobj.seek(0)
            os.environ[ENV_FAPI_CONFIG] = fileobj.name
            yield
        finally:
            if old_fapi_config:
                os.environ[ENV_FAPI_CONFIG] = old_fapi_config


class FAPIMetaClass(BaseContextMetaClass):
    PREFIX = "Fapi_"
    NO_PASS_CTXP = set(["Fapi_Initialize", "Fapi_Finalize", "Fapi_Free"])


class FAPI(Wrapper, metaclass=FAPIMetaClass):

    MODULE = FAPIBinding
    # TODO Verify maximum length requested of GetRandom
    GET_RANDOM_MAX_LENGTH = 64

    def __init__(self, config: Optional[FAPIConfig] = None) -> None:
        self.config = config
        self.ctxpp = None
        self.ctxp = None
        self.logger = logging.getLogger(__name__ + "." + self.__class__.__qualname__)
        self.logger.debug("__init__(%r)", self.config)

    def __enter__(self) -> "FAPIContext":
        # Create an FAPI_CONTEXT **
        ctxpp = self.new_fapi_ctx_ptr()
        # Create an ExitStack
        self.ctx_stack = contextlib.ExitStack().__enter__()
        # Set the config
        self.ctx_stack.enter_context(temp_fapi_config(self.config))
        # Create the FAPI_CONTEXT * and connect to the TPM
        for retry in retry_tcti_loop(max_tries=self.config.tcti_retry):
            with retry_tcti_catch(retry):
                self.Initialize(ctxpp, None)
        # Grab the allocated FAPI_CONTEXT *
        ctxp = self.fapi_ctx_ptr_value(ctxpp)
        # Save references at the end to avoid possible memory leaks
        self.ctxpp = ctxpp
        self.ctxp = ctxp
        # self.logger.debug("__enter__")
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        # Exit the ExitStack
        self.ctx_stack.__exit__(None, None, None)
        # Clean up the FAPI_CONTEXT *
        self.Finalize(self.ctxpp)
        self.delete_fapi_ctx_ptr(self.ctxpp)
        self.ctxpp = None
        self.ctxp = None
        # self.logger.debug("__exit__")

    def _bytearray(self, length, buf):
        """
        Takes any pointer to an array of bytes and that array's length and
        returns a :py:`bytearray` containing those bytes.
        """
        buf = FAPIBinding.ByteArray.frompointer(buf)
        array = bytearray(length)
        for i in range(0, length):
            array[i] = buf[i]
        return array

    @property
    def flush_tr(self):
        """
        Create and return a FAPI_TR_PTR that will be set to FAPI_TR_NONE and
        flushed when it's context exits.
        """
        return partial(FlushTRContext, self)

    @property
    def auth_session(self):
        """
        Create and return a auth session context.
        """
        return partial(AuthSessionContext, self)

    @property
    def nv(self):
        """
        Create and return a nv context.
        """
        return partial(NVContext, self)

    def get_random(self, length: int,) -> ByteString:
        """
        Fapi_GetRandom
        """
        if length > self.GET_RANDOM_MAX_LENGTH:
            raise InvalidArgumentError(
                "Maximum length is {}".format(self.GET_RANDOM_MAX_LENGTH)
            )

        with self.TPM2B_DIGEST_PTR_PTR() as datapp:
            self.GetRandom(length, datapp)

            return self._bytearray(datapp.value.size, datapp.value.buffer)
