# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
from functools import partial
from typing import Optional, ByteString

from .tcti import TCTIContext
from .util.swig import Wrapper
from .binding import AuthSessionContext, ESYSBinding, FlushTRContext, NVContext
from .context import BaseContextMetaClass


class InvalidArgumentError(Exception):
    pass  # pragma: no cov


class ESYSContextMetaClass(BaseContextMetaClass):
    PREFIX = "Esys_"
    NO_PASS_CTXP = set(["Esys_Initialize", "Esys_Finalize"])


class ESYSContext(Wrapper, metaclass=ESYSContextMetaClass):

    MODULE = ESYSBinding
    # TODO Verify maximum length requested of GetRandom
    GET_RANDOM_MAX_LENGTH = 64

    def __init__(self, parent: "ESYS", tcti_ctx: TCTIContext) -> None:
        self.parent = parent
        self.tcti_ctx = tcti_ctx
        self.ctxpp = None
        self.ctxp = None
        # self.logger.debug("__init__")

    def __enter__(self) -> "ESYSContext":
        # Create an ESYS_CONTEXT **
        ctxpp = self.new_ctx_ptr()
        self.Initialize(ctxpp, self.tcti_ctx.ctxp, self.parent.abi_version)
        # Grab the allocated ESYS_CONTEXT *
        ctxp = self.ctx_ptr_value(ctxpp)
        # Save references at the end to avoid possible memory leaks
        self.ctxpp = ctxpp
        self.ctxp = ctxp
        # self.logger.debug("__enter__")
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.Finalize(self.ctxpp)
        self.delete_ctx_ptr(self.ctxpp)
        self.ctxpp = None
        self.ctxp = None
        # self.logger.debug("__exit__")

    def _bytearray(self, length, buf):
        """
        Takes any pointer to an array of bytes and that array's length and
        returns a :py:`bytearray` containing those bytes.
        """
        buf = ESYSBinding.ByteArray.frompointer(buf)
        array = bytearray(length)
        for i in range(0, length):
            array[i] = buf[i]
        return array

    @property
    def flush_tr(self):
        """
        Create and return a ESYS_TR_PTR that will be set to ESYS_TR_NONE and
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

    def get_random(
        self,
        length: int,
        shandle1=ESYSBinding.ESYS_TR_NONE,
        shandle2=ESYSBinding.ESYS_TR_NONE,
        shandle3=ESYSBinding.ESYS_TR_NONE,
    ) -> ByteString:
        """
        Esys_GetRandom
        """
        if length > self.GET_RANDOM_MAX_LENGTH:
            raise InvalidArgumentError(
                "Maximum length is {}".format(self.GET_RANDOM_MAX_LENGTH)
            )

        with self.TPM2B_DIGEST_PTR_PTR() as datapp:
            self.GetRandom(shandle1, shandle2, shandle3, length, datapp)

            return self._bytearray(datapp.value.size, datapp.value.buffer)


class ESYS(Wrapper):

    MODULE = ESYSBinding
    CONTEXT = ESYSContext
    TSS_CREATOR = 1
    TSS_FAMILY = 2
    TSS_LEVEL = 1
    TSS_VERSION = 108

    def __init__(
        self, *, abi_version: Optional[ESYSBinding.TSS2_ABI_VERSION] = None
    ) -> None:
        self.abi_version = (
            abi_version if abi_version is not None else self.default_abi_version()
        )
        # self.logger.debug("__init__")

    def __call__(self, tcti_ctx: TCTIContext) -> "ESYSContext":
        return self.CONTEXT(self, tcti_ctx)

    @classmethod
    def default_abi_version(cls):
        version = cls.MODULE.TSS2_ABI_VERSION()
        version.tssCreator = cls.TSS_CREATOR
        version.tssFamily = cls.TSS_FAMILY
        version.tssLevel = cls.TSS_LEVEL
        version.tssVersion = cls.TSS_VERSION
        # self.logger.debug("created instance of default abi version: %r", version)
        return version
