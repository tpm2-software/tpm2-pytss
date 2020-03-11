# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
import os
import json
import pathlib
from functools import partial, wraps
from typing import Optional, ByteString, NamedTuple

from .util.swig import Wrapper
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


class FAPIConfig(NamedTuple):
    profile_dir: str = DEFAULT_FAPI_CONFIG.get("profile_dir", None)
    user_dir: str = DEFAULT_FAPI_CONFIG.get("user_dir", None)
    system_dir: str = DEFAULT_FAPI_CONFIG.get("system_dir", None)
    log_dir: str = DEFAULT_FAPI_CONFIG.get("log_dir", None)
    profile_name: str = DEFAULT_FAPI_CONFIG.get("profile_name", None)
    tcti: str = DEFAULT_FAPI_CONFIG.get("tcti", None)
    system_pcrs: TPML_PCR_SELECTION_PTR = DEFAULT_FAPI_CONFIG.get("profile_dir", None)
    ek_cert_file: str = DEFAULT_FAPI_CONFIG.get("ek_cert_file", None)
    ek_cert_less: bool = DEFAULT_FAPI_CONFIG.get("ek_cert_less", None)
    ek_fingerprint: TPMT_HA_PTR = DEFAULT_FAPI_CONFIG.get("ek_fingerprint", None)

    def export(self):
        exported = super()._asdict()
        print("FAPIConfig._asdict:", exported)
        return exported

    @classmethod
    def _fromdict(cls, **kwargs):
        print("FAPIConfig._fromdict:", kwargs)
        return cls(**kwargs)


class InvalidArgumentError(Exception):
    pass  # pragma: no cov


class FAPIMetaClass(BaseContextMetaClass):
    PREFIX = "Fapi_"
    NO_PASS_CTXP = set(["Fapi_Initialize", "Fapi_Finalize"])


class FAPI(Wrapper, metaclass=FAPIMetaClass):

    MODULE = FAPIBinding
    # TODO Verify maximum length requested of GetRandom
    GET_RANDOM_MAX_LENGTH = 64

    def __init__(self, config: Optional[FAPIConfig] = None) -> None:
        self.config = config
        self.ctxpp = None
        self.ctxp = None

    def init_config(self, config):
        if config is None and ENV_FAPI_CONFIG in os.environ:
            return
        return

    def __enter__(self) -> "FAPIContext":
        # Create an FAPI_CONTEXT **
        ctxpp = self.new_fapi_ctx_ptr()
        # Set the config

        # Create the FAPI_CONTEXT * and connect to the TPM
        self.Initialize(ctxpp, None)
        # Grab the allocated FAPI_CONTEXT *
        ctxp = self.ctx_ptr_value(ctxpp)
        # Save references at the end to avoid possible memory leaks
        self.ctxpp = ctxpp
        self.ctxp = ctxp
        # self.logger.debug("__enter__")
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
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
