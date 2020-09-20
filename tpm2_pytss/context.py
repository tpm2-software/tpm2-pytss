# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
import json
import inspect
import contextlib
from functools import partial, wraps
from typing import Optional, ByteString

from .tcti import TCTIContext
from .util.swig import Wrapper
from .binding import (
    AuthSessionContext,
    ESYSBinding,
    FlushTRContext,
    NVContext,
    to_bytearray,
)


class InvalidArgumentError(Exception):
    pass  # pragma: no cov


class BaseContextMetaClass(type):
    def __new__(cls, name, bases, props):
        # Create the class
        cls = super(BaseContextMetaClass, cls).__new__(cls, name, bases, props)
        # Go through all the functions in the module
        module = props["MODULE"].__dict__
        for key, func in module.items():
            if key.startswith("_"):
                continue
            # Check if a custom wrapper has been defined for this function
            custom_wrap = getattr(cls, "wrap_{}".format(key), None)
            if custom_wrap is not None:
                func = custom_wrap(func)
            # For all Esys_ functions wrap the function and make the wrapped
            # function a method in our new class
            elif key.startswith(cls.PREFIX):
                if key in cls.NO_PASS_CTXP:
                    func = cls._wrap_no_pass_ctxp(func)
                else:
                    func = cls._wrap_pass_ctxp(func)
            # Remove Esys_ from function names since they will be called from
            # the ESYSContext and that's redundant
            if key.startswith(cls.PREFIX):
                key = key[len(cls.PREFIX) :]
            setattr(cls, key, func)
        return cls

    @classmethod
    def _wrap_no_pass_ctxp(cls, func):
        @wraps(func)
        def wrapper(_self, *args, **kwds):
            """
            wrapper will be assigned to the ESYSContext class as a method. As
            such the first argument, self, is an instance of ESYSContext.
            """
            # Check if a custom wrapper has been defined
            custom_wrap = getattr(cls, "wrap_no_pass_ctxp", None)
            if custom_wrap is not None:
                return custom_wrap(func)(*args, **kwds)
            return func(*args, **kwds)

        return wrapper

    @classmethod
    def _wrap_pass_ctxp(cls, func):
        @wraps(func)
        def wrapper(self, *args, **kwds):
            """
            wrapper will be assigned to the ESYSContext class as a method. As
            such the first argument, self, is an instance of ESYSContext.
            """
            # Check if a custom wrapper has been defined
            custom_wrap = getattr(cls, "wrap_pass_ctxp", None)
            if custom_wrap is not None:
                return custom_wrap(func)(self.ctxp, *args, **kwds)
            return func(self.ctxp, *args, **kwds)

        return wrapper

    @classmethod
    def wrap_pass_ctxp(cls, func):
        """
        Take out pointers and make them tuple return values
        """

        @wraps(func)
        def wrapper(self, *args, **kwds):
            sig = inspect.signature(func.orig)
            parameters = list(sig.parameters.values())

            docstring_arguments = func.orig.__doc__.split("(")[1].split(")")[0]
            # Remove FAPI/ESAPI context pointer
            docstring_arguments = docstring_arguments.split(",")[1:]
            docstring_arguments = map(lambda i: i.strip(), docstring_arguments)
            docstring_arguments = list(docstring_arguments)

            # First missing argument should not be const
            if (
                len(args) < len(docstring_arguments)
                and "const" in docstring_arguments[len(args) :][0].split()
            ):
                for i, docstring in enumerate(docstring_arguments[len(args) :]):
                    # Ensure that all these are arguments that need
                    # allocating
                    if not "**" in docstring:
                        break
                    print(docstring)

            result = func(self, *args, **kwds)

            return_value = []

            skip = False
            for i, (value, docstring) in enumerate(zip(args, docstring_arguments)):
                if skip:
                    skip = False
                    continue
                if not "const" in docstring.split() and "*" in docstring:
                    # char ** arguments are always guaranteed to be NULL
                    # terminated
                    if docstring.startswith("char") and "**" in docstring.split():
                        if value.value is None:
                            return_value.append(None)
                        elif any(map(value.value.startswith, ["[", "{"])):
                            try:
                                return_value.append(json.loads(value.value))
                            except json.decoder.JSONDecodeError:
                                return_value.append(value.value)
                        else:
                            return_value.append(value.value)
                    elif "**" in docstring.split():
                        if (i + 1) < len(docstring_arguments):
                            next_docstring = docstring_arguments[i + 1]
                            next_docstring = next_docstring.split()
                            if (
                                "size_t" in next_docstring
                                and "*" in next_docstring
                                and "uint8_t" in docstring.split()
                            ):
                                return_value.append(
                                    to_bytearray(value.value, args[i + 1].value)
                                )
                                skip = True
                                continue
                        return_value.append(value.value)
                    else:
                        return_value.append(value)

            if len(return_value) > 1:
                return return_value
            elif len(return_value) == 1:
                return return_value[0]
            return result

        return wrapper


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
