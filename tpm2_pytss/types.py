# SPDX-License-Identifier: BSD-2
"""
The types module contains types for each of the corresponding TPM types from the following TCG specifications:

- https://trustedcomputinggroup.org/resource/tpm-library-specification/. See Part 2 "Structures".
- https://trustedcomputinggroup.org/resource/tss-overview-common-structures-specification

The classes contained within can be initialized based on named argument value pairs or dictionaries
of key-value objects where the keys are the names of the associated type.

"""
from ._libtpm2_pytss import ffi, lib

from tpm2_pytss.internal.utils import (
    _chkrc,
    _fixup_cdata_kwargs,
    _cpointer_to_ctype,
    _fixup_classname,
    _convert_to_python_native,
    _mock_bail,
    _ref_parent,
)
from tpm2_pytss.internal.crypto import (
    _calculate_sym_unique,
    _get_digest_size,
    _public_from_encoding,
    _private_from_encoding,
    _public_to_pem,
    _getname,
    _verify_signature,
    private_to_key,
)
import tpm2_pytss.constants as constants  # lgtm [py/import-and-import-from]
from tpm2_pytss.constants import (
    TPMA_OBJECT,
    TPM2_ALG,
    TPM2_ECC_CURVE,
)
from typing import Union, Tuple
import sys

try:
    from tpm2_pytss.internal.type_mapping import _type_map, _element_type_map
except ImportError as e:
    # this is needed so docs can be generated without building
    if "sphinx" not in sys.modules:
        raise e

import binascii
import secrets

from cryptography.hazmat.primitives import serialization


class ParserAttributeError(Exception):
    """ Exception ocurred when when parsing."""

    pass


class TPM2_HANDLE(int):
    """"A handle to a TPM address"""

    pass


class TPM_OBJECT(object):
    """ Abstract Base class for all TPM Objects. Not suitable for direct instantiation."""

    def __init__(self, _cdata=None, **kwargs):

        # Rather than trying to mock the FFI interface, just avoid it and return
        # the base object. This is really only needed for documentation, and it
        # makes it work. Why Yes, this is a terrible hack (cough cough).
        if _mock_bail():
            return

        _cdata, kwargs = _fixup_cdata_kwargs(self, _cdata, kwargs)
        object.__setattr__(self, "_cdata", _cdata)

        tipe = _cpointer_to_ctype(self._cdata)

        expected_cname = _fixup_classname(tipe)
        # Because we alias TPM2B_AUTH as a TPM2B_DIGEST in the C code
        if (
            expected_cname != "TPM2B_DIGEST"
            and expected_cname != self.__class__.__name__
            and "TPM2B_" not in expected_cname
        ):
            raise TypeError(
                f"Unexpected _cdata type {expected_cname}, expected {self.__class__.__name__}"
            )
        fields = {x[0]: x[1].type for x in tipe.fields}
        for k, v in kwargs.items():
            if k not in fields:
                raise AttributeError(
                    f"{self.__class__.__name__} has no field by the name of {k}"
                )
            cname = fields[k]
            if cname.kind != "primitive" and cname.kind != "array":
                clsname = _fixup_classname(cname)
                clazz = globals()[clsname]
                # If subclass object is a TPM2B SIMPLE object, and we have a raw str, or bytes, convert
                if issubclass(clazz, TPM2B_SIMPLE_OBJECT) and isinstance(
                    v, (str, bytes)
                ):
                    _bytefield = clazz._get_bytefield()
                    subobj = clazz(_cdata=None)
                    setattr(subobj, _bytefield, v)
                    v = subobj
            TPM_OBJECT.__setattr__(self, k, v)

    def __getattribute__(self, key):
        try:
            # go through object to avoid invoking THIS objects __getattribute__ call
            # and thus infinite recursion
            return object.__getattribute__(self, key)
        except AttributeError:
            # Ok the object has no idea what you're looking for... can we handle it?
            # Yes we could use self._cdata as it will only recurse once, but lets avoid it.
            _cdata = object.__getattribute__(self, "_cdata")

            # Get the attribute they're looking for out of _cdata
            x = getattr(_cdata, key)

            tm = _type_map.get((self.__class__.__name__, key))
            if tm is not None and hasattr(constants, tm):
                c = getattr(constants, tm)
                obj = c(x)
            elif tm is not None:
                obj = globals()[tm](x)
            else:
                obj = _convert_to_python_native(globals(), x, parent=self._cdata)
            return obj

    def __setattr__(self, key, value):

        _cdata = object.__getattribute__(self, "_cdata")
        if isinstance(value, TPM_OBJECT):
            tipe = ffi.typeof(value._cdata)
            if tipe.kind in ["struct", "union"]:
                value = value._cdata
            else:
                value = value._cdata[0]
        try:
            # Get _cdata without invoking getattr
            setattr(_cdata, key, value)
        except AttributeError:
            return object.__setattr__(self, key, value)
        except TypeError as e:
            data = getattr(_cdata, key)
            tipe = ffi.typeof(data)
            clsname = _fixup_classname(tipe)
            clazz = None
            try:
                clazz = globals()[clsname]
            except KeyError:
                raise e

            _bytefield = clazz._get_bytefield()
            data = getattr(data, _bytefield)
            tipe = ffi.typeof(data)
            if tipe.kind != "array" or not issubclass(clazz, TPM2B_SIMPLE_OBJECT):
                raise e

            if isinstance(value, str):
                value = value.encode()

            subobj = clazz(_cdata=None)
            setattr(subobj, _bytefield, value)
            value = subobj

            # recurse so we can get handling of setattr with Python wrapped data
            setattr(self, key, value)

    def __dir__(self):
        return object.__dir__(self) + dir(self._cdata)

    def marshal(self):
        """Marshal instance into bytes.

        Returns:
            Returns the marshaled type as bytes.
        """
        mfunc = getattr(lib, f"Tss2_MU_{self.__class__.__name__}_Marshal", None)
        if mfunc is None:
            raise RuntimeError(
                f"No marshal function found for {self.__class__.__name__}"
            )
        _cdata = self._cdata
        tipe = ffi.typeof(_cdata)
        if tipe.kind != "pointer":
            _cdata = ffi.new(f"{self.__class__.__name__} *", self._cdata)
        offset = ffi.new("size_t *")
        buf = ffi.new("uint8_t[4096]")
        _chkrc(mfunc(_cdata, buf, 4096, offset))
        return bytes(buf[0 : offset[0]])

    @classmethod
    def unmarshal(cls, buf):
        """Unmarshal bytes into type instance.

        Args:
            buf (bytes): The bytes to be unmarshaled.

        Returns:
            Returns an instance of the current type and the number of bytes consumed.
        """
        umfunc = getattr(lib, f"Tss2_MU_{cls.__name__}_Unmarshal", None)
        if umfunc is None:
            raise RuntimeError(f"No unmarshal function found for {cls.__name__}")
        _cdata = ffi.new(f"{cls.__name__} *")
        offset = ffi.new("size_t *")
        _chkrc(umfunc(buf, len(buf), offset, _cdata))
        return cls(_cdata=_cdata), offset[0]


class TPM2B_SIMPLE_OBJECT(TPM_OBJECT):
    """ Abstract Base class for all TPM2B Simple Objects. A Simple object contains only
    a size and byte buffer fields. This is not suitable for direct instantiation."""

    def __init__(self, _cdata=None, **kwargs):

        _cdata, kwargs = _fixup_cdata_kwargs(self, _cdata, kwargs)
        _bytefield = type(self)._get_bytefield()

        for k, v in kwargs.items():
            if k == "size":
                raise AttributeError(f"{k} is read only")
            if k != _bytefield:
                raise AttributeError(f"{self.__name__} has no field {k}")

            if isinstance(v, str):
                v = v.encode()

            setattr(_cdata, k, v)
            _cdata.size = len(v)

        super().__init__(_cdata=_cdata)

    @classmethod
    def _get_bytefield(cls):
        tipe = ffi.typeof(f"{cls.__name__}")
        for f in tipe.fields:
            if f[0] != "size":
                return f[0]

    def __setattr__(self, key, value):

        if key == "size":
            raise AttributeError(f"{key} is read only")

        _bytefield = type(self)._get_bytefield()
        if key == _bytefield:
            if isinstance(value, str):
                value = value.encode()
            setattr(self._cdata, key, value)
            self._cdata.size = len(value)
        else:
            super().__setattr__(key, value)

    def __getattribute__(self, key):
        _bytefield = type(self)._get_bytefield()
        if key == _bytefield:
            b = getattr(self._cdata, _bytefield)
            rb = _ref_parent(b, self._cdata)
            return memoryview(ffi.buffer(rb, self._cdata.size))
        return super().__getattribute__(key)

    def __len__(self):
        return self._cdata.size

    def __getitem__(self, index):
        _bytefield = type(self)._get_bytefield()
        buf = getattr(self, _bytefield)
        if isinstance(index, int):
            if index >= self._cdata.size:
                raise IndexError("out of range")
            return buf[index]
        elif isinstance(index, slice):
            return buf[index]
        else:
            raise TypeError("index must an int or a slice")

    def __bytes__(self):
        _bytefield = type(self)._get_bytefield()
        buf = getattr(self, _bytefield)
        return bytes(buf)

    def __str__(self) -> str:
        """Returns a hex string representation of the underlying buffer.

        This is the same as:

        .. code-block:: python

            bytes(tpm2b_type).hex()

        Returns (str):
            A hex encoded string of the buffer.
        """
        b = self.__bytes__()
        return binascii.hexlify(b).decode()

    def __eq__(self, value):
        b = self.__bytes__()
        return b == value


class TPML_Iterator(object):
    """ Iterator class for iterating over TPML data types.

    This class is used in enumerated for loops, such as:
    .. code-block:: python

    for alg in TPML_ALG:
       do_something(alg)
    """

    def __init__(self, tpml):
        self._tpml = tpml
        self._index = 0

    def __iter__(self):
        return self

    def __next__(self):

        if self._index > self._tpml.count - 1:
            raise StopIteration

        x = self._tpml[self._index]
        self._index = self._index + 1
        return x


class TPML_OBJECT(TPM_OBJECT):
    """ Abstract Base class for all TPML Objects. A TPML object is an object that
    contains a list of objects. This is not suitable for direct instantiation."""

    def __init__(self, _cdata=None, **kwargs):

        _cdata, kwargs = _fixup_cdata_kwargs(self, _cdata, kwargs)
        super().__init__(_cdata=_cdata)

        # Nothing todo
        if len(kwargs) == 0:
            return

        key = [*kwargs][0]

        cdata_array = self._cdata.__getattribute__(key)

        if isinstance(kwargs[key], TPM_OBJECT):
            kwargs[key] = [kwargs[key]]

        if not isinstance(kwargs[key], (list, tuple)):
            raise TypeError(
                "Expected initializer for TPML data types to be a list or tuple"
            )

        expected_class = TPM_OBJECT
        try:
            tipe = ffi.typeof(cdata_array[0])
            clsname = _fixup_classname(tipe)
            expected_class = globals()[clsname]
        except TypeError:
            pass

        for i, x in enumerate(kwargs[key]):
            if not isinstance(x, (expected_class, int)):
                try:
                    x = expected_class(x)
                except TypeError:
                    # Provide a better error message
                    raise TypeError(
                        f'Expected item at index {i} to be a TPM_OBJECT, got: "{type(x)}"'
                    )

            cdata_array[i] = x._cdata[0] if isinstance(x, TPM_OBJECT) else x

        self._cdata.count = len(kwargs[key])

    def __getattribute__(self, key):

        try:
            # Can the parent handle it?
            x = TPM_OBJECT.__getattribute__(self, key)
            return x
        except TypeError:
            pass

        # Must be a TPML style array
        # Get cdata without implicitly invoking a derived classes __getattribute__
        # This will prevent recursion and stack depth issues.
        _cdata = object.__getattribute__(self, "_cdata")

        # This will invoke the CFFI implementation, so getattr is safe here.
        x = getattr(_cdata, key)

        # If this isn't a CFFI type, something wen't crazy, and typeof() will raise TypeError.
        tipe = ffi.typeof(x)
        if tipe.kind != "array":
            raise TypeError(
                f'Unknown scalar conversion for kind "{tipe.kind}" for key "{key}"'
            )

        # subclasses in the arrays within the CTypes are fixed, so
        # we only need to do this once
        clsname = _fixup_classname(tipe.item)
        subclass = globals()[clsname]

        l = []
        # do not go through __len__
        count = _cdata.count
        for i in range(0, count):
            obj = subclass(_cdata=x[i])
            l.append(obj)

        return l

    def __getitem__(self, item):
        item_was_int = isinstance(item, int)
        try:
            return object.__getitem__(self, item)
        except AttributeError:
            pass

        if not isinstance(item, (int, slice)):
            raise TypeError(
                f"list indices must be integers or slices, not {type(item)}"
            )

        # figure out what part named _cdata to go into
        tipe = ffi.typeof(self._cdata)
        if tipe.kind == "pointer":
            tipe = tipe.item

        field_name = next((v[0] for v in tipe.fields if v[0] != "count"), None)

        if isinstance(item, int):
            item = slice(item, item + 1)

        if item.stop is None:
            item = slice(item.start, len(self) - 1, item.step)

        # get the cdata field
        cdata_list = self._cdata.__getattribute__(field_name)
        cdatas = cdata_list[item]

        tm = _element_type_map.get(self.__class__.__name__)
        if tm is not None and hasattr(constants, tm):
            c = getattr(constants, tm)
            cdatas = [c(x) for x in cdatas]
        elif tm is not None:
            cdatas = [globals()[tm](x) for x in cdatas]

        if len(cdatas) > 0 and not isinstance(cdatas[0], ffi.CData):
            return cdatas[0] if item_was_int else cdatas

        # convert it to python native
        objects = [_convert_to_python_native(globals(), x, self._cdata) for x in cdatas]

        if isinstance(objects[0], TPM2B_SIMPLE_OBJECT):
            objects = [bytes(x) for x in objects]

        return objects[0] if item_was_int else objects

    def __len__(self):

        return self._cdata.count

    def __setitem__(self, key, value):

        if not isinstance(key, (int, slice)):
            raise TypeError(f"list indices must be integers or slices, not {type(key)}")

        if isinstance(key, int) and not isinstance(value, (TPM_OBJECT, int)):
            raise TypeError(
                f"expected value to be TPM_OBJECT or integer not {type(value)}"
            )

        tipe = ffi.typeof(self._cdata)
        if tipe.kind == "pointer":
            tipe = tipe.item

        field_name = next((v[0] for v in tipe.fields if v[0] != "count"), None)

        cdata_list = self._cdata.__getattribute__(field_name)

        # make everything looks like slice
        if isinstance(key, int):
            key = slice(key, key + 1, 1)
            value = [value]
        elif key.step is None:
            key = slice(key.start, key.stop, 1)

        r = range(key.start, key.stop, key.step)
        if len(r) != len(value):
            raise ValueError("Expected {len(r)} items to unpack, got: {len(value)}")

        for value_offset, cdata_offset in enumerate(r):
            x = value[value_offset]
            x = x._cdata[0] if isinstance(x, TPM_OBJECT) else x
            cdata_list[cdata_offset] = x

        if key.stop > self._cdata.count:
            self._cdata.count = key.stop

    def __iter__(self):
        return TPML_Iterator(self)


class TPMU_PUBLIC_PARMS(TPM_OBJECT):
    pass


class TPMT_PUBLIC_PARMS(TPM_OBJECT):
    pass


class TPMT_SYM_DEF_OBJECT(TPM_OBJECT):
    pass


class TPMT_ASYM_SCHEME(TPM_OBJECT):
    pass


class TPM2B_NAME(TPM2B_SIMPLE_OBJECT):
    pass


class TPMT_PUBLIC(TPM_OBJECT):
    @staticmethod
    def _handle_rsa(objstr, templ):
        templ.type = TPM2_ALG.RSA

        if objstr is None or objstr == "":
            objstr = "2048"

        expected = ["1024", "2048", "3072", "4096"]
        if objstr not in expected:
            raise ValueError(
                f'Expected keybits for RSA to be one of {expected}, got:"{objstr}"'
            )

        keybits = int(objstr)
        templ.parameters.rsaDetail.keyBits = keybits

        return True

    @staticmethod
    def _handle_ecc(objstr, templ):
        templ.type = TPM2_ALG.ECC

        if objstr is None or objstr == "":
            curve = TPM2_ECC_CURVE.NIST_P256
        else:
            curve = TPM2_ECC_CURVE.parse(objstr)

        templ.parameters.eccDetail.curveID = curve
        templ.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL

        return True

    @staticmethod
    def _handle_sym_common(objstr):

        if objstr is None or len(objstr) == 0:
            objstr = "128"

        bits = objstr[:3]
        expected = ["128", "192", "256"]
        if bits not in expected:
            raise ValueError(f'Expected bits to be one of {expected}, got: "{bits}"')

        bits = int(bits)

        # go past bits
        objstr = objstr[3:]
        if len(objstr) == 0:
            mode = "null"
        else:
            expected = ["cfb", "cbc", "ofb", "ctr", "ecb"]
            if objstr not in expected:
                raise ValueError(
                    f'Expected mode to be one of {expected}, got: "{objstr}"'
                )
            mode = objstr

        mode = TPM2_ALG.parse(mode)

        return (bits, mode)

    @staticmethod
    def _handle_aes(objstr, templ):
        templ.type = TPM2_ALG.SYMCIPHER
        templ.parameters.symDetail.sym.algorithm = TPM2_ALG.AES

        bits, mode = TPMT_PUBLIC._handle_sym_common(objstr)
        templ.parameters.symDetail.sym.keyBits.sym = bits
        templ.parameters.symDetail.sym.mode.sym = mode
        return False

    @staticmethod
    def _handle_camellia(objstr, templ):
        templ.type = TPM2_ALG.SYMCIPHER
        templ.parameters.symDetail.sym.algorithm = TPM2_ALG.CAMELLIA

        bits, mode = TPMT_PUBLIC._handle_sym_common(objstr)
        templ.parameters.symDetail.sym.keyBits.sym = bits
        templ.parameters.symDetail.sym.mode.sym = mode

        return False

    @staticmethod
    def _handle_xor(_, templ):
        templ.type = TPM2_ALG.KEYEDHASH
        templ.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.XOR

        return True

    @staticmethod
    def _handle_hmac(_, templ):
        templ.type = TPM2_ALG.KEYEDHASH
        templ.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.HMAC

        return True

    @staticmethod
    def _handle_keyedhash(_, templ):
        templ.type = TPM2_ALG.KEYEDHASH
        templ.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL

        return False

    @staticmethod
    def _error_on_conflicting_sign_attrs(templ):
        """
        If the scheme is set, both the encrypt and decrypt attributes cannot be set,
        check to see if this is the case, and turn down:
          - DECRYPT - If its a signing scheme.
          - ENCRYPT - If its an asymmetric enc scheme.

        :param templ: The template to modify
        """

        # Nothing to do
        if templ.parameters.asymDetail.scheme.scheme == TPM2_ALG.NULL:
            return

        is_both_set = bool(templ.objectAttributes & TPMA_OBJECT.SIGN_ENCRYPT) and bool(
            templ.objectAttributes & TPMA_OBJECT.DECRYPT
        )

        # One could smarten this up to behave like tpm2-tools and turn down the attribute, but for now
        # error on bad attribute sets
        if is_both_set:
            raise ParserAttributeError(
                "Cannot set both SIGN_ENCRYPT and DECRYPT in objectAttributes"
            )

    @staticmethod
    def _handle_scheme_rsa(scheme, templ):

        if scheme is None or len(scheme) == 0:
            scheme = "null"

        halg = ""
        # rsaes must match exactly takes no other params
        if scheme == "rsaes":
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.RSAES
            TPMT_PUBLIC._error_on_conflicting_sign_attrs(templ)
            return
        elif scheme == "null":
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.NULL
        elif scheme.startswith("rsassa"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.RSASSA
            halg = scheme[len("rsassa") + 1 :]
        elif scheme.startswith("rsapss"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.RSAPSS
            halg = scheme[len("rsapss") + 1 :]
        elif scheme.startswith("oaep"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.OAEP
            halg = scheme[len("oaep") + 1 :]
        else:
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.NULL
            raise ValueError(
                f'Expected RSA scheme null or rsapss or prefix of rsapss, rsassa, got "{scheme}"'
            )

        if halg == "":
            halg = "sha256"

        templ.parameters.asymDetail.scheme.details.anySig.hashAlg = TPM2_ALG.parse(halg)

        TPMT_PUBLIC._error_on_conflicting_sign_attrs(templ)

        return True

    @staticmethod
    def _handle_scheme_ecc(scheme, templ):

        if scheme is None or len(scheme) == 0:
            scheme = "null"

        halg = ""
        if scheme.startswith("ecdsa"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.ECDSA
            halg = scheme[len("ecdsa") + 1 :]
        elif scheme.startswith("ecdh"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.ECDH
            halg = scheme[len("ecdh") + 1 :]
        elif scheme.startswith("ecschnorr"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.ECSCHNORR
            halg = scheme[len("ecschnorr") + 1 :]
        elif scheme.startswith("ecdaa"):
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.ECDAA
            counter = scheme[5:] if len(scheme) > 5 else "0"
            hunks = counter.split("-")
            counter = hunks[0]
            halg = hunks[1] if len(hunks) > 1 else ""
            templ.parameters.eccDetail.scheme.details.ecdaa.count = int(counter)
        elif scheme == "null":
            templ.parameters.eccDetail.scheme.scheme = TPM2_ALG.NULL
        else:
            templ.parameters.asymDetail.scheme.scheme = TPM2_ALG.NULL
            raise ValueError(
                f'Expected EC scheme null or prefix of oaep, ecdsa, ecdh, scshnorr, ecdaa, got "{scheme}"'
            )

        if halg == "":
            halg = "sha256"

        templ.parameters.asymDetail.scheme.details.anySig.hashAlg = TPM2_ALG.parse(halg)

        TPMT_PUBLIC._error_on_conflicting_sign_attrs(templ)

        return True

    @staticmethod
    def _handle_scheme_keyedhash(scheme, templ):

        if scheme is None or scheme == "":
            scheme = "sha256"

        halg = TPM2_ALG.parse(scheme)
        if templ.parameters.keyedHashDetail.scheme.scheme == TPM2_ALG.HMAC:
            templ.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = halg
        elif templ.parameters.keyedHashDetail.scheme.scheme == TPM2_ALG.XOR:
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = halg
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = (
                TPM2_ALG.KDF1_SP800_108
            )
        else:
            raise ValueError(
                f'Expected one of HMAC or XOR, got: "{templ.parameters.keyedHashDetail.scheme.scheme}"'
            )

    @staticmethod
    def _handle_scheme(scheme, templ):
        if templ.type == TPM2_ALG.RSA:
            TPMT_PUBLIC._handle_scheme_rsa(scheme, templ)
        elif templ.type == TPM2_ALG.ECC:
            TPMT_PUBLIC._handle_scheme_ecc(scheme, templ)
        elif templ.type == TPM2_ALG.KEYEDHASH:
            TPMT_PUBLIC._handle_scheme_keyedhash(scheme, templ)
        else:
            # TODO make __str__ routine for int types
            raise ValueError(
                f'Expected object to be of type RSA, ECC or KEYEDHASH, got "{templ.type}"'
            )

    @staticmethod
    def _handle_asymdetail(detail, templ):

        if templ.type == TPM2_ALG.KEYEDHASH:
            if detail is not None:
                raise ValueError(
                    f'Keyedhash objects cannot have asym detail, got: "{detail}"'
                )
            return

        if templ.type != TPM2_ALG.RSA and templ.type != TPM2_ALG.ECC:
            raise ValueError(
                f'Expected only RSA and ECC objects to have asymdetail, got: "{templ.type}"'
            )

        is_restricted = bool(templ.objectAttributes & TPMA_OBJECT.RESTRICTED)
        is_rsapss = templ.parameters.asymDetail.scheme.scheme == TPM2_ALG.RSAPSS

        if detail is None or detail == "":
            detail = "aes128cfb" if is_restricted or is_rsapss else "null"

        if detail == "null":
            templ.parameters.symDetail.sym.algorithm = TPM2_ALG.NULL
            return

        if detail.startswith("aes"):
            templ.parameters.symDetail.sym.algorithm = TPM2_ALG.AES
            detail = detail[3:]
        elif detail.startswith("camellia"):
            templ.parameters.symDetail.sym.algorithm = TPM2_ALG.CAMELLIA
            detail = detail[8:]
        else:
            raise ValueError(
                f'Expected symmetric detail to be null or start with one of aes, camellia, got: "{detail}"'
            )

        bits, mode = TPMT_PUBLIC._handle_sym_common(detail)
        templ.parameters.symDetail.sym.keyBits.sym = bits
        templ.parameters.symDetail.sym.mode.sym = mode

    @classmethod
    def parse(
        cls,
        alg: str = "rsa",
        objectAttributes: Union[
            TPMA_OBJECT, int, str
        ] = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS,
        nameAlg: Union[TPM2_ALG, int, str] = "sha256",
        authPolicy: bytes = None,
    ) -> "TPMT_PUBLIC":
        """Builds a TPMT_PUBLIC from a tpm2-tools like specifier strings.

        This builds the TPMT_PUBLIC structure which can be used in TPM2_Create and TPM2_CreatePrimary
        commands that map into the tpm2-tools project as tpm2 create and createprimary commandlets. Those
        commands take options: -G, -n, -L and -a option to specify the object to create. This method
        converts those options, but does not create the object like tpm2-tools.

        Args:
            alg (str): The string specifier for the objects algorithm type, bitsize, symmetric cipher
                and scheme. This is tpm2-tools option "-G" as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#complex-specifiers.

            objectAttiributes (TPMA_OBJECT, int, str): The objects attributes whihch can either the object attributes
                themselves or a nice name string value. This is tpm2-tools option "-a as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/obj-attrs.md.

            nameAlg (TPM2_ALG, int, str): The hashing algorithm for the objects name, either the TPM2_ALG constant,
                integer value or a friendly name string. This is tpm2-tools option "-n" as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#hashing-algorithms

            authPolicy (bytes): The policy digest of the object. This is tpm2-tools option "-L".

        Returns:
            A populated TPMT_PUBLIC for use.

        Raises:
            ValueError: If a string value is not of an expected format.

        Examples:
            .. code-block:: python

                TPMT_PUBLIC.parse(
                    "ecc:ecdh-sha384",
                    objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS)

                TPMT_PUBLIC.parse(
                    alg="xor:sha512",
                    nameAlg="sha256",
                    authPolicy=b'\xc5\x81sS\xf2\x9bc\x87r\xdf\x01\xd3\xbaowM\x96Q\xaf\x1a\xeeKEO\x82\xfeV\xf3\x13^[\x87')
        """
        templ = TPMT_PUBLIC()

        if isinstance(nameAlg, str):
            nameAlg = TPM2_ALG.parse(nameAlg)
        templ.nameAlg = nameAlg

        if isinstance(objectAttributes, str):
            objectAttributes = TPMA_OBJECT.parse(objectAttributes)
        templ.objectAttributes = objectAttributes

        if authPolicy is not None:
            templ.authPolicy = authPolicy

        alg = alg.lower()

        hunks = alg.split(":")
        objstr = hunks[0].lower()
        scheme = hunks[1].lower() if len(hunks) > 1 else None
        symdetail = hunks[2].lower() if len(hunks) > 2 else None

        expected = ("rsa", "ecc", "aes", "camellia", "xor", "hmac", "keyedhash")

        keep_processing = False
        prefix = tuple(filter(lambda x: objstr.startswith(x), expected))
        if len(prefix) == 1:
            prefix = prefix[0]
            keep_processing = getattr(TPMT_PUBLIC, f"_handle_{prefix}")(
                objstr[len(prefix) :], templ
            )
        else:
            raise ValueError(
                f'Expected object prefix to be one of {expected}, got: "{objstr}"'
            )

        if not keep_processing:
            if scheme:
                raise ValueError(
                    f'{prefix} objects cannot have additional specifiers, got: "{scheme}"'
                )
            return templ

        # at this point we either have scheme as a scheme or an asym detail
        try:
            TPMT_PUBLIC._handle_scheme(scheme, templ)
        except ValueError as e:
            # nope try it as asymdetail
            symdetail = scheme

        TPMT_PUBLIC._handle_asymdetail(symdetail, templ)

        return templ

    @classmethod
    def from_pem(
        cls,
        data: bytes,
        nameAlg: Union[TPM2_ALG, int] = TPM2_ALG.SHA256,
        objectAttributes: Union[TPMA_OBJECT, int] = (
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        symmetric: TPMT_SYM_DEF_OBJECT = None,
        scheme: TPMT_ASYM_SCHEME = None,
        password: bytes = None,
    ) -> "TPMT_PUBLIC":
        """Decode the public part from standard key encodings.

        Currently supports PEM, DER and SSH encoded public keys.

        Args:
            data (bytes): The encoded public key.
            nameAlg (TPM2_ALG, int): The name algorithm for the public area, default is TPM2_ALG.SHA256.
            objectAttributes (TPMA_OBJECT, int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            symmetric (TPMT_SYM_DEF_OBJECT) optional: The symmetric definition to use for the public area, default is None.
            scheme (TPMT_ASYM_SCHEME) optional: The signing/key exchange scheme to use for the public area, default is None.
            password (bytes) optional: The password used to decrypt the key, default is None.

        Returns:
            Returns a TPMT_PUBLIC instance.

        Raises:
            ValueError: If key parameters are not supported.

        Example:
            .. code-block:: python

                ecc_key_pem = open('path/to/myecckey.pem').read().encode()
                TPMT_PUBLIC.from_pem(ecc_key_pem)
        """
        p = cls()
        _public_from_encoding(data, p, password=password)
        p.nameAlg = nameAlg
        if isinstance(objectAttributes, str):
            objectAttributes = TPMA_OBJECT.parse(objectAttributes)
        p.objectAttributes = objectAttributes
        if symmetric is None:
            p.parameters.asymDetail.symmetric.algorithm = TPM2_ALG.NULL
        elif isinstance(symmetric, str):
            TPMT_PUBLIC._handle_asymdetail(symmetric, p)
        else:
            p.parameters.asymDetail.symmetric = symmetric
        if scheme is None:
            p.parameters.asymDetail.scheme.scheme = TPM2_ALG.NULL
        elif isinstance(scheme, str):
            TPMT_PUBLIC._handle_scheme(scheme, p)
        else:
            p.parameters.asymDetail.scheme = scheme
        if p.type == TPM2_ALG.ECC:
            p.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
        return p

    def to_pem(self) -> bytes:
        """Encode the public key as PEM encoded ASN.1.

        Returns:
            Returns the PEM encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.publicArea.to_pem()
        """

        return _public_to_pem(self, "pem")

    def to_der(self) -> bytes:
        """Encode the public key as DER encoded ASN.1.

        Returns:
            Returns the DER encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.publicArea.to_der()
        """

        return _public_to_pem(self, "der")

    def to_ssh(self) -> bytes:
        """Encode the public key in OpenSSH format

        Returns:
            Returns the OpenSSH encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.publicArea.to_ssh()
        """

        return _public_to_pem(self, "ssh")

    def get_name(self) -> TPM2B_NAME:
        """Get the TPM name of the public area.

        This function requires a populated TPMT_PUBLIC and will NOT go to the TPM
        to retrieve the name, and instead calculates it manually.

        Returns:
            Returns TPM2B_NAME.

        Raises:
            ValueError: Unsupported name digest algorithm.
        """
        name = _getname(self)
        return TPM2B_NAME(name)


class TPM2B_ATTEST(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_CONTEXT_DATA(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_CONTEXT_SENSITIVE(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_CREATION_DATA(TPM_OBJECT):
    pass


class TPM2B_DATA(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_DIGEST(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_ECC_PARAMETER(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_ECC_POINT(TPM_OBJECT):
    pass


class TPM2B_ENCRYPTED_SECRET(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_EVENT(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_ID_OBJECT(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_IV(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_MAX_BUFFER(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_MAX_NV_BUFFER(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_NV_PUBLIC(TPM_OBJECT):
    def get_name(self) -> TPM2B_NAME:
        """Get the TPM name of the NV public area.

        This function requires a populated TPM2B_NV_PUBLIC and will NOT go to the TPM
        to retrieve the name, and instead calculates it manually.

        Returns:
            Returns TPM2B_NAME.

        Raises:
            ValueError: Unsupported name digest algorithm.
        """
        return self.nvPublic.get_name()


class TPM2B_PRIVATE(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_PRIVATE_KEY_RSA(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_PRIVATE_VENDOR_SPECIFIC(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_PUBLIC(TPM_OBJECT):
    @classmethod
    def from_pem(
        cls,
        data: bytes,
        nameAlg: Union[TPM2_ALG, int] = TPM2_ALG.SHA256,
        objectAttributes: Union[TPMA_OBJECT, int] = (
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        symmetric: TPMT_SYM_DEF_OBJECT = None,
        scheme: TPMT_ASYM_SCHEME = None,
        password: bytes = None,
    ) -> "TPM2B_PUBLIC":
        """Decode the public part from standard key encodings.

        Currently supports PEM, DER and SSH encoded public keys.

        Args:
            data (bytes): The encoded public key.
            nameAlg (TPM2_ALG, int): The name algorithm for the public area, default is TPM2_ALG.SHA256.
            objectAttributes (TPMA_OBJECT, int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            symmetric (TPMT_SYM_DEF_OBJECT) optional: The symmetric definition to use for the public area, default is None.
            scheme (TPMT_ASYM_SCHEME) optional: The signing/key exchange scheme to use for the public area, default is None.
            password (bytes) optional: The password used to decrypt the key, default is None.

        Returns:
            Returns a TPMT_PUBLIC instance.

        Raises:
            ValueError: If key parameters are not supported.

        Example:
            .. code-block:: python

                ecc_key_pem = open('path/to/myecckey.pem').read().encode()
                TP2B_PUBLIC.from_pem(ecc_key_pem)
        """

        pa = TPMT_PUBLIC.from_pem(
            data, nameAlg, objectAttributes, symmetric, scheme, password
        )
        p = cls(publicArea=pa)
        return p

    def to_pem(self) -> bytes:
        """Encode the public key as PEM encoded ASN.1.

        Returns:
            Returns the PEM encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.to_pem()
        """

        return self.publicArea.to_pem()

    def to_der(self) -> bytes:
        """Encode the public key as DER encoded ASN.1.

        Returns:
            Returns the DER encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.to_der()
        """

        return self.publicArea.to_der()

    def to_ssh(self) -> bytes:
        """Encode the public key in OpenSSH format

        Returns:
            Returns the OpenSSH encoded key as bytes.

        Raises:
            ValueError: If key type is not supported.

        Example:
            .. code-block:: python

                with ESAPI() as e:
                    # public parameter is index 1 in the return tuple
                    pub = e.create_primary(None)[1]
                    pub.to_ssh()
        """

        return self.publicArea.to_ssh()

    def get_name(self) -> TPM2B_NAME:
        """Get the TPM name of the public area.

        This function requires a populated TPM2B_PUBLIC and will NOT go to the TPM
        to retrieve the name, and instead calculates it manually.

        Returns:
            Returns TPM2B_NAME.

        Raises:
            ValueError: Unsupported name digest algorithm.
        """
        return self.publicArea.get_name()

    @classmethod
    def parse(
        cls,
        alg="rsa",
        objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS,
        nameAlg="sha256",
        authPolicy=None,
    ) -> "TPM2B_PUBLIC":
        """Builds a TPM2B_PUBLIC from a tpm2-tools like specifier strings.

        This builds the TPM2B_PUBLIC structure which can be used in TPM2_Create and TPM2_CreatePrimary
        commands that map into the tpm2-tools project as tpm2 create and createprimary commandlets. Those
        commands take options: -G, -n, -L and -a option to specify the object to create. This method
        converts those options, but does not create the object like tpm2-tools.

        Args:
            alg (str): The string specifier for the objects algorithm type, bitsize, symmetric cipher
                and scheme. This is tpm2-tools option "-G" as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#complex-specifiers.

            objectAttiributes (TPMA_OBJECT, int, str): The objects attributes whihch can either the object attributes
                themselves or a nice name string value. This is tpm2-tools option "-a as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/obj-attrs.md.

            nameAlg (TPM2_ALG, int, str): The hashing algorithm for the objects name, either the TPM2_ALG constant,
                integer value or a friendly name string. This is tpm2-tools option "-n" as described in:
                https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#hashing-algorithms

            authPolicy (bytes): The policy digest of the object. This is tpm2-tools option "-L".

        Returns:
            A populated TPMT_PUBLIC for use.

        Raises:
            ValueError: If a string value is not of an expected format.

        Examples:
            .. code-block:: python

                TPM2B_PUBLIC.parse(
                    "ecc:ecdh-sha384",
                    objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS)

                TPM2B_PUBLIC.parse(
                    alg="xor:sha512",
                    nameAlg="sha256",
                    authPolicy=b'\xc5\x81sS\xf2\x9bc\x87r\xdf\x01\xd3\xbaowM\x96Q\xaf\x1a\xeeKEO\x82\xfeV\xf3\x13^[\x87')
        """

        return cls(TPMT_PUBLIC.parse(alg, objectAttributes, nameAlg, authPolicy))


class TPM2B_PUBLIC_KEY_RSA(TPM2B_SIMPLE_OBJECT):
    pass


class TPMT_KEYEDHASH_SCHEME(TPM_OBJECT):
    pass


class TPM2B_SENSITIVE(TPM_OBJECT):
    @classmethod
    def from_pem(cls, data: bytes, password: bytes = None) -> "TPM2B_SENSITIVE":
        """Decode the private part from standard key encodings.

        Currently supports PEM, DER and SSH encoded private keys.

        Args:
            data (bytes): The encoded key as bytes.
            password (bytes, optional): The password used to decrypt the key, default is None.

        Returns:
            Returns an instance of TPM2B_SENSITIVE.

        Raises:
            ValueError: If key parameters are not supported.

        Example:
            .. code-block:: python

                rsa_private_key = open('path/to/my/rsaprivatekey.pem').read().encode()
                TPM2B_SENSITIVE.from_pem(rsa_private_key)
        """
        p = TPMT_SENSITIVE.from_pem(data, password)
        return cls(sensitiveArea=p)

    @classmethod
    def keyedhash_from_secret(
        cls,
        secret: bytes,
        nameAlg: Union[TPM2_ALG, int] = TPM2_ALG.SHA256,
        objectAttributes: Union[TPMA_OBJECT, int] = (
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        scheme: TPMT_KEYEDHASH_SCHEME = None,
        seed: bytes = None,
    ) -> Tuple["TPM2B_SENSITIVE", TPM2B_PUBLIC]:
        """Generate the private and public part for a keyed hash object from a secret.

        Args:
            secret (bytes): The HMAC key / data to be sealed.
            nameAlg (TPM2_ALG, int): The name algorithm for the public part, default is TPM2_ALG.SHA256.
            objectAttributes (TPMA_OBJECT, int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            scheme (TPMT_KEYEDHASH_SCHEME) optional: The signing/key exchange scheme to use for the public area, default is None.
            seed (bytes) optional: The obfuscate value, default is a randomized value.

        Returns:
            A tuple of TPM2B_SENSITIVE and TPM2B_PUBLIC

        Raises:
            ValueError: If key parameters are not supported.

        Example:
            .. code-block:: python

                secret = b"secret key"
                scheme = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.HMAC)
                scheme.details.hmac.hashAlg = TPM2_ALG.SHA256
                (sens, pub) = TPM2B_SENSITIVE.keyedhash_from_secret(secret, scheme=scheme)
        """
        sa, pa = TPMT_SENSITIVE.keyedhash_from_secret(
            secret, nameAlg, objectAttributes, scheme, seed
        )
        priv = TPM2B_SENSITIVE(sensitiveArea=sa)
        pub = TPM2B_PUBLIC(publicArea=pa)
        return (priv, pub)

    @classmethod
    def symcipher_from_secret(
        cls,
        secret: bytes,
        algorithm: Union[TPM2_ALG, int] = TPM2_ALG.AES,
        mode: Union[TPM2_ALG, int] = TPM2_ALG.CFB,
        nameAlg: Union[TPM2_ALG, int] = TPM2_ALG.SHA256,
        objectAttributes: Union[TPMA_OBJECT, int] = (
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        seed: bytes = None,
    ) -> Tuple["TPM2B_SENSITIVE", TPM2B_PUBLIC]:
        """Generate the private and public part for a symcipher object from a secret.

        Args:
            secret (bytes): the symmetric key.
            algorithm (TPM2_ALG, int): The symmetric cipher algorithm to use, default is TPM2_ALG.AES.
            mode (TPM2_ALG. int): The symmetric mode to use, default is TPM2_ALG.CFB.
            nameAlg (TPM2_ALG, int): The name algorithm for the public part, default is TPM2_ALG.SHA256.
            objectAttributes (TPMA_OBJECT, int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            seed (bytes) optional: The obfuscate value, default is a randomized value.

        Returns:
            A tuple of TPM2B_SENSITIVE and TPM2B_PUBLIC

        Example:
            .. code-block:: python

                secret = b"\xF1" * 32
                sens, pub = TPM2B_SENSITIVE.symcipher_from_secret(secret)
        """
        sa, pa = TPMT_SENSITIVE.symcipher_from_secret(
            secret, algorithm, mode, nameAlg, objectAttributes, seed
        )
        priv = TPM2B_SENSITIVE(sensitiveArea=sa)
        pub = TPM2B_PUBLIC(publicArea=pa)
        return (priv, pub)

    def to_pem(self, public: TPMT_PUBLIC, password=None) -> bytes:
        """Encode the key as PEM encoded ASN.1.

        Args:
            public(TPMT_PUBLIC): The corresponding public key.
            password(bytes): An optional password for encrypting the PEM with.

        Returns:
            Returns the PEM encoding as bytes.

        Raises:
            ValueError: Unsupported key type.

        Example:
            .. code-block:: python

                rsa_private_key = open('path/to/my/rsaprivatekey.pem').read().encode()
                priv = TPM2B_SENSITIVE.from_pem(rsa_private_key)
                pub = TPM2B_PUBLIC.from_pem(rsa_private_key)
                priv.to_pem(pub.publicArea)
        """
        return self.sensitiveArea.to_pem(public, password)

    def to_der(self, public: TPMT_PUBLIC) -> bytes:
        """Encode the key as DER encoded ASN.1.

        public(TPMT_PUBLIC): The corresponding public key.

        Returns:
            Returns the DER encoding as bytes.

        Raises:
            ValueError: Unsupported key type.

        Example:
            .. code-block:: python

                rsa_private_key = open('path/to/my/rsaprivatekey.pem').read().encode()
                priv = TPM2B_SENSITIVE.from_pem(rsa_private_key)
                pub = TPM2B_PUBLIC.from_pem(rsa_private_key)
                priv.to_der(pub.publicArea)
        """

        return self.sensitiveArea.to_der(public)

    def to_ssh(self, public: TPMT_PUBLIC, password: bytes = None) -> bytes:
        """Encode the key as OPENSSH PEM format.

        Args:
            public(TPMT_PUBLIC): The corresponding public key.
            password(bytes): An optional password for encrypting the PEM with.

        Returns:
            Returns the PEM OPENSSH encoding as bytes.

        Raises:
            ValueError: Unsupported key type.

        Example:
            .. code-block:: python

                rsa_private_key = open('path/to/my/rsaprivatekey.pem').read().encode()
                priv = TPM2B_SENSITIVE.from_pem(rsa_private_key)
                pub = TPM2B_PUBLIC.from_pem(rsa_private_key)
                priv.to_ssh(pub.publicArea)
        """

        return self.sensitiveArea.to_ssh(public, password=password)


class TPM2B_SENSITIVE_CREATE(TPM_OBJECT):
    pass


class TPM2B_SENSITIVE_DATA(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_SYM_KEY(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_TEMPLATE(TPM2B_SIMPLE_OBJECT):
    pass


class TPML_AC_CAPABILITIES(TPML_OBJECT):
    pass


class TPML_ALG(TPML_OBJECT):
    @classmethod
    def parse(cls, algorithms: str) -> "TPML_ALG":
        """Convert an comma separated list of algorithm friendly string names to a list of numeric constants.

        Friendly algorithm names are the constants representing algorithms found in the TPM2_ALG class.
        The string identifiers are those understood by TPM2_ALG.parse.

        Args:
            algorithms(str): A comma separated list of algorithm friendly names. May be a list of one item with no
                comma.

        Returns:
            A populated TPML_ALG

        Raises:
            ValueError: Invalid algorithms list.

        Example:
            .. code-block:: python

                TPML_ALG("aes")
                TPML_ALG("aes,sha256")
        """

        if algorithms is None or len(algorithms) == 0:
            raise ValueError(
                f"Expected algorithms to be not None or len > 0, got: {algorithms}"
            )

        alglist = []
        for a in algorithms.split(","):
            a = a.strip()
            if len(a) > 0:
                alglist.append(TPM2_ALG.parse(a))

        if len(alglist) == 0:
            raise ValueError(f'No algorithms found in algorithms, got "{algorithms}"')

        return TPML_ALG(alglist)


class TPML_ALG_PROPERTY(TPML_OBJECT):
    pass


class TPML_CC(TPML_OBJECT):
    pass


class TPML_CCA(TPML_OBJECT):
    pass


class TPML_DIGEST(TPML_OBJECT):
    pass


class TPML_DIGEST_VALUES(TPML_OBJECT):
    pass


class TPML_ECC_CURVE(TPML_OBJECT):
    pass


class TPML_HANDLE(TPML_OBJECT):
    pass


class TPML_INTEL_PTT_PROPERTY(TPML_OBJECT):
    pass


class TPML_PCR_SELECTION(TPML_OBJECT):
    @staticmethod
    def parse(selections: str) -> "TPML_PCR_SELECTION":
        """Convert a PCR selection string into the TPML_PCR_SELECTION data structure.

        PCR Bank Selection lists follow the below specification: ::

        <BANK>:<PCR>[,<PCR>] or <BANK>:all

        multiple banks may be separated by '+'.

        For Example "sha1:3,4+sha256:all", will select PCRs 3 and 4 from the SHA1 bank
        and PCRs 0 to 23 from the SHA256 bank.

        Args:
            algorithms(str): A comma separated list of algorithm friendly names. May be a list of one item with no
                comma.

        Returns:
            A populated TPML_PCR_SELECTION

        Raises:
            ValueError: Invalid algorithms list.

        Example:
            .. code-block:: python

                TPML_PCR_SELECTION.parse("sha256:1,3,5,7")
                TPML_PCR_SELECTION.parse("sha1:3,4+sha256:all")
        """

        if selections is None or len(selections) == 0:
            return TPML_PCR_SELECTION()

        selectors = selections.split("+") if "+" in selections else [selections]

        if len(selectors) - 1 != selections.count("+"):
            raise ValueError(
                f"Malformed PCR bank selection list (unbalanced +), got: {selections}"
            )

        for x in selectors:
            if len(x) == 0:
                raise ValueError(
                    f"Malformed PCR bank selection list (unbalanced +), got: {selections}"
                )

        count = len(selectors)
        if count > lib.TPM2_NUM_PCR_BANKS:
            raise ValueError(
                f"PCR Selection list greater than {lib.TPM2_NUM_PCR_BANKS}, "
                f"got {len(selectors)}"
            )

        selections = [TPMS_PCR_SELECTION.parse(x) for x in selectors]

        return TPML_PCR_SELECTION(selections)


class TPML_TAGGED_PCR_PROPERTY(TPML_OBJECT):
    pass


class TPML_TAGGED_TPM_PROPERTY(TPML_OBJECT):
    pass


class TPMS_AC_OUTPUT(TPM_OBJECT):
    pass


class TPMS_ALGORITHM_DESCRIPTION(TPM_OBJECT):
    pass


class TPMS_ALGORITHM_DETAIL_ECC(TPM_OBJECT):
    pass


class TPMS_ALG_PROPERTY(TPM_OBJECT):
    pass


class TPMS_ASYM_PARMS(TPM_OBJECT):
    pass


class TPMU_ATTEST(TPM_OBJECT):
    pass


class TPMS_ATTEST(TPM_OBJECT):
    pass


class TPMS_AUTH_COMMAND(TPM_OBJECT):
    pass


class TPMS_AUTH_RESPONSE(TPM_OBJECT):
    pass


class TPMU_CAPABILITIES(TPM_OBJECT):
    pass


class TPMS_CAPABILITY_DATA(TPM_OBJECT):
    pass


class TPMS_CERTIFY_INFO(TPM_OBJECT):
    pass


class TPMS_CLOCK_INFO(TPM_OBJECT):
    pass


class TPMS_COMMAND_AUDIT_INFO(TPM_OBJECT):
    pass


class TPMS_CONTEXT(TPM_OBJECT):
    @classmethod
    def from_tools(cls, data: bytes) -> "TPMS_CONTEXT":
        """Unmarshal a tpm2-tools context blob.

        Note:
            Currently only support key object contexts from tpm2-tools.

        Args:
            data (bytes): The bytes from a tpm2-tools context file.

        Returns:
            Returns a TPMS_CONTEXT instance.
        """
        magic = int.from_bytes(data[0:4], byteorder="big")
        if magic != 0xBADCC0DE:
            raise ValueError(f"bad magic, expected 0xBADCC0DE, got 0x{magic:X}")
        version = int.from_bytes(data[4:8], byteorder="big")
        if version != 1:
            raise ValueError(f"bad version, expected 1, got {version}")
        ctx = cls()
        ctx.hierarchy = int.from_bytes(data[8:12], byteorder="big")
        ctx.savedHandle = int.from_bytes(data[12:16], byteorder="big")
        ctx.sequence = int.from_bytes(data[16:24], byteorder="big")
        ctx.contextBlob, _ = TPM2B_CONTEXT_DATA.unmarshal(data[24:])
        return ctx


class TPMS_CONTEXT_DATA(TPM_OBJECT):
    pass


class TPMS_CREATION_DATA(TPM_OBJECT):
    pass


class TPMS_CREATION_INFO(TPM_OBJECT):
    pass


class TPMS_ECC_PARMS(TPM_OBJECT):
    pass


class TPMS_ECC_POINT(TPM_OBJECT):
    pass


class TPMS_EMPTY(TPM_OBJECT):
    pass


class TPMS_ID_OBJECT(TPM_OBJECT):
    pass


class TPMS_KEYEDHASH_PARMS(TPM_OBJECT):
    pass


class TPMS_NV_CERTIFY_INFO(TPM_OBJECT):
    pass


class TPMS_NV_PIN_COUNTER_PARAMETERS(TPM_OBJECT):
    pass


class TPMS_NV_PUBLIC(TPM_OBJECT):
    def get_name(self) -> TPM2B_NAME:
        """Get the TPM name of the NV public area.

        Returns:
            Returns TPM2B_NAME.
        """
        name = _getname(self)
        return TPM2B_NAME(name)


class TPMS_PCR_SELECT(TPM_OBJECT):
    pass


class TPMS_PCR_SELECTION(TPM_OBJECT):
    def __init__(self, pcrs=None, **kwargs):
        super().__init__(**kwargs)

        if not pcrs:
            return

        if bool(self.hash) != bool(pcrs):
            raise ValueError("hash and pcrs MUST be specified")

        self._cdata.sizeofSelect = 3

        if pcrs == "all" or (len(pcrs) == 1 and pcrs[0] == "all"):
            self._cdata.pcrSelect[0] = 0xFF
            self._cdata.pcrSelect[1] = 0xFF
            self._cdata.pcrSelect[2] = 0xFF
            return

        for pcr in pcrs:
            if pcr < 0 or pcr > lib.TPM2_PCR_LAST:
                raise ValueError(f"PCR Index out of range, got {pcr}")
            self._cdata.pcrSelect[pcr // 8] |= 1 << (pcr % 8)

    @staticmethod
    def parse(selection: str) -> "TPMS_PCR_SELECTION":
        """Given a PCR selection string populate a TPMS_PCR_SELECTION structure.

        A PCR Bank selection lists: ::

        <BANK>:<PCR>[,<PCR>] or <BANK>:all

        For Example "sha1:3,4", will select PCRs 3 and 4 from the SHA1 bank.

        Args:
            selection(str): A PCR selection string.

        Returns:
            A populated TPMS_PCR_SELECTION

        Raises:
            ValueError: Invalid PCR specification.

        Example:
            .. code-block:: python

                TPMS_PCR_SELECTION.parse("sha256:1,3,5,7")
                TPMS_PCR_SELECTION.parse("sha1:all")
        """

        if selection is None or len(selection) == 0:
            raise ValueError(
                f'Expected selection to be not None and len > 0, got: "{selection}"'
            )

        hunks = [x.strip() for x in selection.split(":")]
        if len(hunks) != 2:
            raise ValueError(f"PCR Selection malformed, got {selection}")

        try:
            halg = int(hunks[0], 0)
        except ValueError:
            halg = TPM2_ALG.parse(hunks[0])

        if hunks[1] != "all":
            try:
                pcrs = [int(x.strip(), 0) for x in hunks[1].split(",")]
            except ValueError:
                raise ValueError(f"Expected PCR number, got {hunks[1]}")
        else:
            pcrs = hunks[1]

        return TPMS_PCR_SELECTION(hash=halg, pcrs=pcrs)


class TPMS_QUOTE_INFO(TPM_OBJECT):
    pass


class TPMS_RSA_PARMS(TPM_OBJECT):
    pass


class TPMS_SCHEME_ECDAA(TPM_OBJECT):
    pass


class TPMS_SCHEME_HASH(TPM_OBJECT):
    pass


class TPMS_SCHEME_XOR(TPM_OBJECT):
    pass


class TPMS_SENSITIVE_CREATE(TPM_OBJECT):
    pass


class TPMS_SESSION_AUDIT_INFO(TPM_OBJECT):
    pass


class TPMS_SIGNATURE_ECC(TPM_OBJECT):
    pass


class TPMS_SIGNATURE_RSA(TPM_OBJECT):
    pass


class TPMS_SYMCIPHER_PARMS(TPM_OBJECT):
    pass


class TPMS_TAGGED_PCR_SELECT(TPM_OBJECT):
    pass


class TPMS_TAGGED_PROPERTY(TPM_OBJECT):
    pass


class TPMS_TIME_ATTEST_INFO(TPM_OBJECT):
    pass


class TPMS_TIME_INFO(TPM_OBJECT):
    pass


class TPMT_ECC_SCHEME(TPM_OBJECT):
    pass


class TPMU_ASYM_SCHEME(TPM_OBJECT):
    pass


class TPMT_KDF_SCHEME(TPM_OBJECT):
    pass


class TPMT_TK_CREATION(TPM_OBJECT):
    pass


class TPMT_RSA_SCHEME(TPM_OBJECT):
    pass


class TPMU_SYM_KEY_BITS(TPM_OBJECT):
    pass


class TPMU_SYM_MODE(TPM_OBJECT):
    pass


class TPMT_SYM_DEF(TPM_OBJECT):
    pass


class TPM2B_AUTH(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_NONCE(TPM2B_SIMPLE_OBJECT):
    pass


class TPMU_PUBLIC_ID(TPM_OBJECT):
    pass


class TPMT_SENSITIVE(TPM_OBJECT):
    @classmethod
    def from_pem(cls, data, password=None):
        """Decode the private part from standard key encodings.

        Currently supports PEM, DER and SSH encoded private keys.

        Args:
            data (bytes): The encoded key as bytes.
            password (bytes, optional): The password used to decrypt the key, default is None.

        Returns:
            Returns an instance of TPMT_SENSITIVE.
        """
        p = cls()
        _private_from_encoding(data, p, password)
        return p

    @classmethod
    def keyedhash_from_secret(
        cls,
        secret,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        scheme=None,
        seed=None,
    ):
        """Generate the private and public part for a keyed hash object from a secret.

        Args:
            secret (bytes): The HMAC key / data to be sealed.
            nameAlg (int): The name algorithm for the public part, default is TPM2_ALG.SHA256.
            objectAttributes (int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            scheme (TPMT_KEYEDHASH_SCHEME, optional): The signing/key exchange scheme to use for the public area, default is None.
            seed (bytes, optional): The obfuscate value, default is a randomized value.

        Returns:
            A tuple of of TPMT_SENSITIVE and TPMT_PUBLIC
        """
        pub = TPMT_PUBLIC(
            type=TPM2_ALG.KEYEDHASH, nameAlg=nameAlg, objectAttributes=objectAttributes
        )
        if scheme is None:
            pub.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
        else:
            pub.parameters.keyedHashDetail.scheme = scheme
        digsize = _get_digest_size(nameAlg)
        if seed and len(seed) != digsize:
            raise ValueError(
                f"invalid seed size, expected {digsize} but got {len(seed)}"
            )
        elif not seed:
            seed = secrets.token_bytes(digsize)
        pub.unique.keyedHash = _calculate_sym_unique(nameAlg, secret, seed)
        priv = cls(sensitiveType=TPM2_ALG.KEYEDHASH)
        priv.sensitive.bits = secret
        priv.seedValue = seed
        return (priv, pub)

    @classmethod
    def symcipher_from_secret(
        cls,
        secret,
        algorithm=TPM2_ALG.AES,
        mode=TPM2_ALG.CFB,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        seed=None,
    ):
        """
        Generate the private and public part for a symcipher object from a secret.

        Args:
            secret (bytes): the symmetric key.
            algorithm (int): The symmetric cipher algorithm to use, default is TPM2_ALG.AES.
            mode (int): The symmetric mode to use, default is TPM2_ALG.CFB.
            nameAlg (int): The name algorithm for the public part, default is TPM2_ALG.SHA256.
            objectAttributes (int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            seed (bytes, optional): The obfuscate value, default is a randomized value.

        Returns:
            A tuple of TPMT_SENSITIVE and TPMT_PUBLIC
        """
        nbits = len(secret) * 8
        if algorithm == TPM2_ALG.SM4 and nbits != 128:
            raise ValueError(f"invalid key size, expected 128, got {nbits}")
        elif nbits not in (128, 192, 256):
            raise ValueError(
                f"invalid key size, expected 128, 192 or 256 bits, got {nbits}"
            )
        pub = TPMT_PUBLIC(
            type=TPM2_ALG.SYMCIPHER, nameAlg=nameAlg, objectAttributes=objectAttributes
        )
        pub.parameters.symDetail.sym.keyBits.sym = nbits
        pub.parameters.symDetail.sym.algorithm = algorithm
        pub.parameters.symDetail.sym.mode.sym = mode
        digsize = _get_digest_size(nameAlg)
        if seed and len(seed) != digsize:
            raise ValueError(
                f"invalid seed size, expected {digsize} but got {len(seed)}"
            )
        elif not seed:
            seed = secrets.token_bytes(digsize)
        pub.unique.sym = _calculate_sym_unique(nameAlg, secret, seed)
        priv = cls(sensitiveType=TPM2_ALG.SYMCIPHER)
        priv.sensitive.bits = secret
        priv.seedValue = seed
        return (priv, pub)

    def _serialize(
        self,
        encoding: str,
        public: TPMT_PUBLIC,
        format: str = serialization.PrivateFormat.TraditionalOpenSSL,
        password: bytes = None,
    ):
        k = private_to_key(self, public)

        enc_alg = (
            serialization.NoEncryption()
            if password is None
            else serialization.BestAvailableEncryption(password)
        )

        data = k.private_bytes(
            encoding=encoding, format=format, encryption_algorithm=enc_alg,
        )

        return data

    def to_pem(self, public: TPMT_PUBLIC, password: bytes = None):
        """Encode the key as PEM encoded ASN.1.

        public(TPMT_PUBLIC): The corresponding public key.
        password(bytes): An optional password for encrypting the PEM with.

        Returns:
            Returns the PEM encoding as bytes.
        """

        return self._serialize(serialization.Encoding.PEM, public, password=password)

    def to_der(self, public: TPMT_PUBLIC):
        """Encode the key as DER encoded ASN.1.

        public(TPMT_PUBLIC): The corresponding public key.

        Returns:
            Returns the DER encoding as bytes.
        """

        return self._serialize(serialization.Encoding.DER, public)

    def to_ssh(self, public: TPMT_PUBLIC, password: bytes = None):
        """Encode the key as SSH format.

        public(TPMT_PUBLIC): The corresponding public key.
        password(bytes): An optional password for encrypting the PEM with.

        Returns:
            Returns the DER encoding as bytes.
        """

        return self._serialize(
            serialization.Encoding.PEM,
            public,
            format=serialization.PrivateFormat.OpenSSH,
            password=password,
        )


class TPMU_SENSITIVE_COMPOSITE(TPM_OBJECT):
    pass


class TPMU_SCHEME_KEYEDHASH(TPM_OBJECT):
    pass


class TPMT_RSA_DECRYPT(TPM_OBJECT):
    pass


class TPMT_TK_HASHCHECK(TPM_OBJECT):
    pass


class TPMT_HA(TPM_OBJECT):
    def __bytes__(self) -> bytes:
        """Returns the digest field as bytes.

        If the hashAlg field is TPM2_ALG.NULL, it returns
        bytes object of len 0.

        Return:
            The digest field as bytes.
        """
        if self.hashAlg == TPM2_ALG.NULL:
            return b""
        ds = _get_digest_size(self.hashAlg)
        return bytes(self.digest.sha512[0:ds])


class TPMU_HA(TPM_OBJECT):
    pass


class TPMT_SIG_SCHEME(TPM_OBJECT):
    pass


class TPMU_SIGNATURE(TPM_OBJECT):
    pass


class TPMT_SIGNATURE(TPM_OBJECT):
    def verify_signature(self, key, data):
        """
        Verify a TPM generated signature against a key.

        Args:
            key (TPMT_PUBLIC, TPM2B_PUBLIC or bytes): The key to verify against, bytes for HMAC, the public part for asymmetric key.
            data (bytes): The signed data to verify.

        Raises:
            InvalidSignature: when the signature doesn't match the data.
        """
        _verify_signature(self, key, data)


class TPMU_SIG_SCHEME(TPM_OBJECT):
    pass


class TPMT_TK_VERIFIED(TPM_OBJECT):
    pass


class TPM2B_TIMEOUT(TPM_OBJECT):
    pass


class TPMT_TK_AUTH(TPM_OBJECT):
    pass


class TPM2B_OPERAND(TPM2B_SIMPLE_OBJECT):
    pass
