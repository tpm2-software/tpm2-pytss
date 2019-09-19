import inspect
import logging
from functools import partial, wraps
from typing import Any

# logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


class Wrapper:
    """
    SWIG does a great job. This class takes SWIG outputs and makes them a bit
    more Pythonic.
    """

    def __getattribute__(self, name):
        try:
            return super().__getattribute__(name)
        except AttributeError:
            for attempt in [
                partial(self._pointer_class, module=self.MODULE),
                lambda name: self.MODULE.__dict__.get(name, AttributeError),
            ]:
                prop = attempt(name)
                if prop is not AttributeError:
                    return prop
            raise

    @classmethod
    def _pointer_class(cls, name, *, module=None):
        """
        Creates a class of the requested pointer functions data type
        which supports context management.
        """
        check = {
            "_new": "new_{}",
            "_copy": "copy_{}",
            "_delete": "delete_{}",
            "_assign": "{}_assign",
            "_value": "{}_value",
        }
        # Look up the methods
        for key, value in check.items():
            check[key] = module.__dict__.get(value.format(name), None)
        if not all(check.values()):
            return AttributeError
        return type(name, (ContextManagedPointerClass,), check)


class WrapperMetaClass(type, Wrapper):
    # Enable changing function arguments of one value into another before they
    # are passed to the swig function. This allows us to create abstractions on
    # top of the swig abstractions to make the interface more user friendly.
    CALL_MODS = set()

    def __init__(cls, name, bases, namespace, **kwargs):
        """
        Needed for compatibility with Python 3.5
        """
        super().__init__(name, bases, namespace)

    def __new__(cls, name, bases, props, module=None):
        # Set the module
        props["MODULE"] = module
        # Create the class
        cls = super(WrapperMetaClass, cls).__new__(cls, name, bases, props)
        # Go through all the functions in the module
        for key, func in module.__dict__.items():
            if not key.startswith("_") and inspect.isfunction(func):
                func = cls.wrap(func)
                setattr(cls, key, func)
        return cls

    def __getattribute__(cls, name):
        try:
            return object.__getattribute__(cls, name)
        except AttributeError:
            module = object.__getattribute__(cls, "MODULE")
            for attempt in [
                partial(cls._pointer_class, module=module),
                lambda name: module.__dict__.get(name, AttributeError),
            ]:
                prop = attempt(name)
                if prop is not AttributeError:
                    return prop
            raise

    @classmethod
    def register_call_mod(cls, mod):
        cls.CALL_MODS.add(mod)
        return mod

    @classmethod
    def wrap(cls, func):
        sig = inspect.signature(func)
        parameters = list(sig.parameters.values())

        @wraps(func)
        def wrapper(*args, **kwargs):
            """
            wrapper will be assigned to the ESYSContext class as a method. As
            such the first argument, self, is an instance of ESYSContext
            """
            args = list(args)
            # Combine the arguments we were passed and the parameters from the
            # signature and loop through them all.
            for i, (value, parameter) in enumerate(zip(args, parameters)):
                # Go through each of the call modifiers and use the returned
                # value as the new value for the argument if it was not None
                for modify in cls.CALL_MODS:
                    modifed = modify(parameter.name, parameter.annotation, value)
                    if modifed is not None:
                        args[i] = modifed
            LOGGER.debug(
                ("%s(\n    " % (func.__name__,))
                + "\n    ".join(
                    map(lambda x: "%s: %s," % (x[0].name, x[1]), zip(parameters, args))
                )
                + "\n)"
            )
            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def call_mod_ptr_or_value(annotation, value):
        """
        Last step in a call_mod_ for classes which wrap swig types and expose them
        via ``value`` and ``ptr`` properties.
        """
        # If a pointer is being requested, then pass the SessionContext pointer. Do
        # this by checking if the reverse of the string representation of the value
        # starts in a *, aka the last charater in the type is a * (for pointer)
        if annotation[::-1].startswith("*"):
            return value.ptr
        # Otherwise we pass the value that is being pointed to by the SessionContext
        # pointer
        return value.value


class ContextManagedPointerClass:
    def __init__(self, *, ptr: Any = None):
        self.ptr = ptr

    @property
    def value(self) -> Any:
        return self._value(self.ptr)

    @value.setter
    def value(self, value) -> None:
        self._assign(self.ptr, value)

    @classmethod
    def frompointer(cls, ptr: Any) -> "ContextManagedPointerClass":
        return cls(ptr)

    def __enter__(self):
        if self.ptr is None:
            self.ptr = self._new()
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self._delete(self.ptr)
        self.ptr = None


@WrapperMetaClass.register_call_mod
def call_mod_context_managed_pointer_class(name, annotation, value):
    if isinstance(value, ContextManagedPointerClass):
        return WrapperMetaClass.call_mod_ptr_or_value(annotation, value)
