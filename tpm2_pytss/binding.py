import os
import abc
import sys
import inspect
import pkgutil
from contextlib import contextmanager, _GeneratorContextManager
from typing import Any, Callable, Optional, List

from . import exceptions
from .util.swig import WrapperMetaClass, pointer_class, ContextManagedPointerClass
from .util.calculate import calculate
from .esys_binding import *
from .fapi_binding import *

# MODULE_NAME = "tpm2_pytss"
MODULE_NAME = ".".join(__name__.split(".")[:-1])
esys_binding = sys.modules[MODULE_NAME + ".esys_binding"]
fapi_binding = sys.modules[MODULE_NAME + ".fapi_binding"]

# TODO signature with return type of TPM_RC
for prefix, module in [("Esys_", esys_binding), ("Fapi_", fapi_binding)]:
    exceptions.wrap_funcs(
        module,
        dst=[module, sys.modules[__name__]],
        cond=lambda key, func: key.startswith(prefix) or key.startswith("Tss2_"),
    )

    exceptions.wrap_funcs(
        module,
        dst=[module, sys.modules[__name__]],
        cond=lambda key, func: key.startswith("Tss2_MU_"),
        wrapperfunc=exceptions.raise_tpm2_mu_error,
    )


class NoPointerClass(Exception):
    """
    Happens when there is no pointer for a SWIG value, shouldn't ever happen.
    """

    pass  # pragma: no cov


def wrap_all_matching(
    wrapper_func: Callable[[str, Any], Callable],
    src,
    dst: Optional[List[Any]] = None,
    cond: Optional[Callable[[Callable], bool]] = None,
):
    """
    Wrap the functions within the given module with a decorator so that if they
    return integer values that are non-zero an error will be thrown.
    """
    if dst is None:
        dst = [src]
    for key, value in inspect.getmembers(src):
        if cond is None or cond(key, value):
            value = wrapper_func(key, value)
            for obj in dst:
                setattr(obj, key, value)
    return dst


class SetPropertiesViaInit:
    """
    SWIG creates python classes but doesn't let us set their properties when
    passing arguments to their ``__init__`` method. This class is meant to
    subclass from those swig classes to allow for that functionality.
    """

    def __init__(self, **kwargs):
        sig = inspect.signature(self.SWIG_CLS)
        if sig.parameters:
            self.SWIG_CLS.__init__(self, **kwargs)
        else:
            self.SWIG_CLS.__init__(self)
        for key, value in kwargs.items():
            # For arrays which are not BYTEs within structures we check if
            # attempting to set the value threw an exception complaining about
            # the wrong data type. If it did and the value is a list or tuple,
            # then set each index.
            try:
                if isinstance(value, dict) and not len(value):
                    continue
                setattr(self, key, value)
            except TypeError as error:
                if not isinstance(value, (tuple, list, set, bytes, bytearray)):
                    error.args = (error.args[0] + " but got %r" % (value),)
                    raise
                str_error = str(error)
                if not "argument 2 of type" in str_error:
                    raise
                str_error = str_error.split("argument 2 of type")
                str_error = str_error[-1].replace("'", "")
                str_error = str_error.strip()
                # Split the type name from the size of the array
                type_name, max_size = str_error.split(" ")
                if not (max_size.startswith("[") and max_size[::-1].startswith("]")):
                    raise
                max_size = calculate(
                    sys.modules[__name__], max_size.replace("[", "").replace("]", "")
                )
                # Grab the array verion of the type
                array_cls = getattr(sys.modules[__name__], type_name + "_ARRAY")
                # Create the array version and assign to each index
                array = array_cls.frompointer(getattr(self, key))
                # Copy each index
                for i in range(0, min(len(value), max_size)):
                    array[i] = value[i]

    @contextmanager
    def ptr(self):
        ptr_cls = ESYSBinding.MODULE.__dict__.get("{}_PTR".format(self.NAME), None)
        if ptr_cls is None:
            raise NoPointerClass(self.NAME)
        # TODO If the value of the pointer changes then we need to set the
        # properites of this object to be whatever they were changed to in the
        # pointers object (Since we can't accually point to this value)
        with ptr_cls(self) as ptr:
            yield ptr


def set_properties_via_init(name, cls):
    """
    SWIG creates python classes but doesn't let us set their properties when
    passing arguments to their ``__init__`` method. Grab the class and use
    it and SetPropertiesViaInit to create a new class which will allow for
    that functionality.
    """
    return type(name, (SetPropertiesViaInit, cls), {"NAME": name, "SWIG_CLS": cls})


for module in [esys_binding, fapi_binding]:
    wrap_all_matching(
        set_properties_via_init,
        module,
        dst=[module, sys.modules[__name__]],
        cond=lambda key, value: inspect.isclass(value) and key.upper() == key,
    )


class ByteArrayHelper:
    def __init__(self, **kwargs):
        # kwargs which need to be copied from a list or bytearry into a C array
        convert_buffer = {}
        for size_prop, buffer_prop, buffer_max in self.BYTEARRAYS:
            if buffer_prop in kwargs:
                # Skip if not a python type
                if not isinstance(kwargs[buffer_prop], (tuple, list, bytes, bytearray)):
                    continue
                if buffer_prop == "pcrSelections":
                    continue
                # Add to buffers to be converted
                convert_buffer[buffer_prop] = kwargs[buffer_prop]
                # Remove from kwargs so they don't get set
                del kwargs[buffer_prop]
            if size_prop in kwargs:
                # Remove from kwargs so they don't get set
                del kwargs[size_prop]
        self.BYTEARRAY_CLS.__init__(self, **kwargs)
        for size_prop, buffer_prop, buffer_max in self.BYTEARRAYS:
            # Skip buffers we weren't given
            if buffer_prop not in convert_buffer:
                continue
            buffer_data = convert_buffer[buffer_prop]
            if len(buffer_data) > buffer_max:
                raise ValueError(
                    "{} of size {} is larger than maximum of {}".format(
                        buffer_prop, len(buffer_data), buffer_max
                    )
                )
            # Set size
            setattr(self, size_prop, len(buffer_data))
            # Set elements of buffer
            buffer_ptr = ByteArray.frompointer(getattr(self, buffer_prop))
            for i, value in enumerate(buffer_data):
                buffer_ptr[i] = value


BYTEARRAY_STRUCTURES = {
    "TPM2B_DIGEST": [("size", "buffer", sizeof_TPMU_HA)],
    "TPM2B_DATA": [("size", "buffer", sizeof_TPMU_HA)],
    "TPM2B_EVENT": [("size", "buffer", 1024)],
    "TPM2B_MAX_BUFFER": [("size", "buffer", TPM2_MAX_DIGEST_BUFFER)],
    "TPM2B_MAX_NV_BUFFER": [("size", "buffer", TPM2_MAX_NV_BUFFER_SIZE)],
    "TPM2B_IV": [("size", "buffer", TPM2_MAX_SYM_BLOCK_SIZE)],
    "TPM2B_NAME": [("size", "name", sizeof_TPMU_NAME)],
    "TPMS_PCR_SELECT": [("sizeofSelect", "pcrSelect", TPM2_PCR_SELECT_MAX)],
    "TPMS_PCR_SELECTION": [("sizeofSelect", "pcrSelect", TPM2_PCR_SELECT_MAX)],
    "TPMS_TAGGED_PCR_SELECT": [("sizeofSelect", "pcrSelect", TPM2_PCR_SELECT_MAX)],
    "TPML_CC": [("count", "commandCodes", TPM2_MAX_CAP_CC)],
    "TPML_CCA": [("count", "commandAttributes", TPM2_MAX_CAP_CC)],
    "TPML_ALG": [("count", "algorithms", TPM2_MAX_ALG_LIST_SIZE)],
    "TPML_HANDLE": [("count", "handle", TPM2_MAX_CAP_HANDLES)],
    "TPML_DIGEST": [("count", "digests", 8)],
    "TPML_DIGEST_VALUES": [("count", "digests", TPM2_NUM_PCR_BANKS)],
    "TPML_PCR_SELECTION": [("count", "pcrSelections", TPM2_NUM_PCR_BANKS)],
    "TPML_ALG_PROPERTY": [("count", "algProperties", TPM2_MAX_CAP_ALGS)],
    "TPML_TAGGED_TPM_PROPERTY": [("count", "tpmProperty", TPM2_MAX_TPM_PROPERTIES)],
    "TPML_TAGGED_PCR_PROPERTY": [("count", "pcrProperty", TPM2_MAX_PCR_PROPERTIES)],
    "TPML_ECC_CURVE": [("count", "eccCurves", TPM2_MAX_ECC_CURVES)],
    "TPML_INTEL_PTT_PROPERTY": [("count", "property", TPM2_MAX_PTT_PROPERTIES)],
    "TPM2B_ATTEST": [("size", "attestationData", sizeof_TPMS_ATTEST)],
    "TPM2B_SYM_KEY": [("size", "buffer", TPM2_MAX_SYM_KEY_BYTES)],
    "TPM2B_SENSITIVE_DATA": [("size", "buffer", TPM2_MAX_SYM_DATA)],
    "TPM2B_PUBLIC_KEY_RSA": [("size", "buffer", TPM2_MAX_RSA_KEY_BYTES)],
    "TPM2B_PRIVATE_KEY_RSA": [("size", "buffer", TPM2_MAX_RSA_KEY_BYTES / 2)],
    "TPM2B_ECC_PARAMETER": [("size", "buffer", TPM2_MAX_ECC_KEY_BYTES)],
    "TPM2B_ENCRYPTED_SECRET": [("size", "secret", sizeof_TPMU_ENCRYPTED_SECRET)],
    "TPM2B_TEMPLATE": [("size", "buffer", sizeof_TPMT_PUBLIC)],
    "TPM2B_PRIVATE_VENDOR_SPECIFIC": [
        ("size", "buffer", TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES)
    ],
    "TPM2B_PRIVATE": [("size", "buffer", sizeof__PRIVATE)],
    "TPM2B_ID_OBJECT": [("size", "credential", sizeof_TPMS_ID_OBJECT)],
    "TPM2B_CONTEXT_SENSITIVE": [("size", "buffer", TPM2_MAX_CONTEXT_SIZE)],
    "TPM2B_CONTEXT_DATA": [("size", "buffer", sizeof_TPMS_CONTEXT_DATA)],
    "TPML_AC_CAPABILITIES": [("count", "acCapabilities", TPM2_MAX_AC_CAPABILITIES)],
}


def bytearray_helper(name, cls):
    """
    For structures which have internal buffers named "buffer", this function
    modifes those classes so that we can set the buffer from an array and it
    gets returned as a bytearray.
    """
    return type(
        name,
        (ByteArrayHelper, cls),
        {"BYTEARRAY_CLS": cls, "BYTEARRAYS": BYTEARRAY_STRUCTURES[name]},
    )


for module in [esys_binding, fapi_binding]:
    wrap_all_matching(
        bytearray_helper,
        module,
        dst=[module, sys.modules[__name__]],
        cond=lambda key, value: key in BYTEARRAY_STRUCTURES,
    )


def to_bytearray(length, buf):
    """
    Takes any pointer to an array of bytes and that array's length and
    returns a :py:func:`bytearray` containing those bytes.
    """
    buf = ByteArray.frompointer(buf)
    array = bytearray(length)
    for i in range(0, length):
        array[i] = buf[i]
    return array


def var_name(search, str_value):
    """
    Try to find the variable name for the variable ``search`` within the caller
    stack.
    """
    for stack in inspect.stack():
        # Don't care about variable names within tpm2_pytss or contextlib
        # (ExitStack)
        if stack.frame.f_code.co_filename.startswith(
            os.path.dirname(sys.modules[MODULE_NAME].__file__)
        ) or stack.frame.f_code.co_filename.startswith(
            os.path.dirname(sys.modules["contextlib"].__file__)
        ):
            continue
        for variable_name, variable in stack.frame.f_locals.items():
            if variable is search:
                return variable_name
    return str_value


class TRContext(abc.ABC):
    def __init__(self, esys_ctx: "ESYSContext") -> None:
        self.esys_ctx = esys_ctx
        self.ptr = None

    def __enter__(self) -> "TRContext":
        self.ptr = ESYS_TR_PTR()
        self.value = self.esys_ctx.ESYS_TR_NONE
        return self

    @abc.abstractmethod
    def __exit__(self, _exc_type, _exc_value, _traceback):
        pass  # pragma: no cov

    @property
    def value(self):
        return self.ptr.value()

    @value.setter
    def value(self, updated):
        return self.ptr.assign(updated)


@WrapperMetaClass.register_call_mod
def call_mod_tr_context(name, annotation, value):
    # Bail out if the value we're trying to pass isn't a TRContext
    if not isinstance(value, TRContext):
        return
    return WrapperMetaClass.call_mod_ptr_or_value(annotation, value)


class FlushTRContextFlushFailure(Exception):
    """
    Raised when FlushContext results in a TPM2Error. On exit from the
    FlushTRContext.
    """


class FlushTRContext(TRContext):
    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self.value is not None and self.value != self.esys_ctx.ESYS_TR_NONE:
            try:
                self.esys_ctx.FlushContext(self.value)
            except exceptions.TPM2Error as error:
                raise FlushTRContextFlushFailure(var_name(self, self.value)) from error
        self.ptr = False


class AuthSessionContext(FlushTRContext):
    def __init__(self, esys_ctx: "ESYSContext", *args) -> None:
        super().__init__(esys_ctx)
        sig = inspect.signature(self.esys_ctx.StartAuthSession)
        if len(args) != (len(sig.parameters) - 1):
            raise ValueError("Wrong number of arguments")
        for arg, parameter in zip(args, sig.parameters.values()):
            setattr(self, parameter.name, arg)

    def __enter__(self) -> "TRContext":
        super().__enter__()
        self.esys_ctx.StartAuthSession(
            self.tpmKey,
            self.bind,
            self.shandle1,
            self.shandle2,
            self.shandle3,
            self.nonceCaller,
            self.sessionType,
            self.symmetric,
            self.authHash,
            self.ptr,
        )
        return self


class NVContextUndefineSpaceFailure(Exception):
    """
    Raised when NV_UndefineSpace results in a TPM2Error. On exit from the
    NVContext.
    """


# TODO This and AuthSessionContext should be generated on the file using inspect to
# get the arguments of the Define/Undefine and StartAuthSession/Flush
# arguments.
class NVContext(TRContext):
    """
    NV_DefineSpace on enter and NV_UndefineSpace on exit.
    """

    def __init__(
        self,
        esys_ctx: "ESYSContext",
        authHandle=None,
        shandle1=ESYS_TR_NONE,
        shandle2=ESYS_TR_NONE,
        shandle3=ESYS_TR_NONE,
        auth=None,
        publicInfo=None,
    ) -> None:
        super().__init__(esys_ctx)
        self.authHandle = authHandle
        self.shandle1 = shandle1
        self.shandle2 = shandle2
        self.shandle3 = shandle3
        self.auth = auth
        self.publicInfo = publicInfo

    def __enter__(self) -> "TRContext":
        super().__enter__()
        self.esys_ctx.NV_DefineSpace(
            self.authHandle,
            self.shandle1,
            self.shandle2,
            self.shandle3,
            self.auth,
            self.publicInfo,
            self.ptr,
        )
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self.value is not None and self.value != self.esys_ctx.ESYS_TR_NONE:
            try:
                self.esys_ctx.NV_UndefineSpace(
                    self.authHandle,
                    self.value,
                    self.shandle1,
                    self.shandle2,
                    self.shandle3,
                )
            except exceptions.TPM2Error as error:
                raise NVContextUndefineSpaceFailure(
                    var_name(self, self.value)
                ) from error
        self.ptr = False


class UsedWithoutEnteringContext(Exception):
    """
    Attempted to use a pointer without being in a ``with`` block for that
    pointer.
    """

    pass  # pragma: no cov


@WrapperMetaClass.register_call_mod
def call_mod_context_managed_pointer_class(name, annotation, value):
    if isinstance(value, _GeneratorContextManager):
        raise UsedWithoutEnteringContext(name)
    if isinstance(value, ContextManagedPointerClass):
        if value.ptr is None:
            raise UsedWithoutEnteringContext(name)
        return WrapperMetaClass.call_mod_ptr_or_value(annotation, value)


# Create all the ContextManagedPointerClasses to be used for the
# pointer_functions
for module in [esys_binding, fapi_binding]:
    for name, func in inspect.getmembers(module):
        if (
            name.startswith("new_")
            and module.__dict__.get(name.replace("new_", "delete_")) is not None
        ):
            name = name[len("new_") :]
            ptr_ptr = pointer_class(name, module=module)
            if ptr_ptr is AttributeError:
                continue
            setattr(sys.modules[__name__], name, ptr_ptr)
            setattr(module, name, ptr_ptr)


def typedef_map():
    """
    SWIG uses typedefs to allow passing a pointer of one type to a function that
    accepts a different type. However, it does not generate aliases for all
    typedefs.

    aka

    typedef A B;

    user would need to create an instance by the name of A when they want to use
    B. This maps B to A so the user can instantiate B without having to know
    that B is the same thing as A.
    """
    return dict(
        [
            line.replace(";", "").split()[-2:][::-1]
            for line in pkgutil.get_data(__name__.split(".")[0], "swig/tpm2_types.i")
            .decode()
            .split("\n")
            if line.startswith("typedef")
        ]
    )


TYPEDEFS = typedef_map()

for module in [esys_binding, fapi_binding]:
    for alias, typename in TYPEDEFS.items():
        for alias, typename in zip(
            [alias, "{}_PTR".format(alias), "{}_PTR_PTR".format(alias)],
            [typename, "{}_PTR".format(typename), "{}_PTR_PTR".format(typename)],
        ):
            # Skip if it already exists
            if sys.modules[__name__].__dict__.get(alias) is not None:
                continue
            reference = sys.modules[__name__].__dict__.get(typename)
            if reference is None:
                continue
            setattr(module, alias, type(alias, (reference,), {}))
            setattr(sys.modules[__name__], alias, type(alias, (reference,), {}))


class ESYSBinding(metaclass=WrapperMetaClass, module=esys_binding):

    MODULE = esys_binding


class FAPIBinding(metaclass=WrapperMetaClass, module=fapi_binding):

    MODULE = fapi_binding
