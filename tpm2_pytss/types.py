"""
SPDX-License-Identifier: BSD-2
"""

from ._libtpm2_pytss import ffi, lib

from tpm2_pytss.internal.utils import (
    _chkrc,
    _fixup_cdata_kwargs,
    _cpointer_to_ctype,
    _fixup_classname,
    _convert_to_python_native,
    _mock_bail,
)
from tpm2_pytss.internal.crypto import (
    _calculate_sym_unique,
    _get_digest_size,
    _public_from_encoding,
    _private_from_encoding,
    _public_to_pem,
    _getname,
    _verify_signature,
)
from tpm2_pytss.constants import (
    TPMA_OBJECT,
    TPM2_ALG,
    TPM2_ECC_CURVE,
)

import binascii
import secrets


class ParserAttributeError(Exception):
    pass


class TPM2_HANDLE(int):
    pass


class TPM_OBJECT(object):
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

            obj = _convert_to_python_native(globals(), x)
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
            return memoryview(ffi.buffer(b, self._cdata.size))
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

    def __str__(self):
        b = self.__bytes__()
        return binascii.hexlify(b).decode()

    def __eq__(self, value):
        b = self.__bytes__()
        return b == value


class TPML_Iterator(object):
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

        if len(cdatas) > 0 and not isinstance(cdatas[0], ffi.CData):
            return cdatas[0] if item_was_int else cdatas

        # convert it to python native
        objects = [_convert_to_python_native(globals(), x) for x in cdatas]

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


class TPMT_PUBLIC(TPM_OBJECT):
    @staticmethod
    def _handle_rsa(objstr, templ):
        templ.type = TPM2_ALG.RSA

        if objstr is None or objstr == "":
            objstr = "2048"

        expected = ["1024", "2048", "3072", "4096"]
        if objstr not in expected:
            raise RuntimeError(
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
            raise RuntimeError(f'Expected bits to be one of {expected}, got: "{bits}"')

        bits = int(bits)

        # go past bits
        objstr = objstr[3:]
        if len(objstr) == 0:
            mode = "null"
        else:
            expected = ["cfb", "cbc", "ofb", "ctr", "ecb"]
            if objstr not in expected:
                raise RuntimeError(
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
            raise RuntimeError(
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
            raise RuntimeError(
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
            raise RuntimeError(
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
            raise RuntimeError(
                f'Expected object to be of type RSA, ECC or KEYEDHASH, got "{templ.type}"'
            )

    @staticmethod
    def _handle_asymdetail(detail, templ):

        if templ.type == TPM2_ALG.KEYEDHASH:
            if detail is not None:
                raise RuntimeError(
                    f'Keyedhash objects cannot have asym detail, got: "{detail}"'
                )
            return

        if templ.type != TPM2_ALG.RSA and templ.type != TPM2_ALG.ECC:
            raise RuntimeError(
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
            raise RuntimeError(
                f'Expected symmetric detail to be null or start with one of aes, camellia, got: "{detail}"'
            )

        bits, mode = TPMT_PUBLIC._handle_sym_common(detail)
        templ.parameters.symDetail.sym.keyBits.sym = bits
        templ.parameters.symDetail.sym.mode.sym = mode

    @classmethod
    def parse(
        cls,
        alg="rsa",
        objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS,
        nameAlg="sha256",
        authPolicy=None,
    ):

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
            raise RuntimeError(
                f'Expected object prefix to be one of {expected}, got: "{objstr}"'
            )

        if not keep_processing:
            if scheme:
                raise RuntimeError(
                    f'{prefix} objects cannot have additional specifiers, got: "{scheme}"'
                )
            return templ

        # at this point we either have scheme as a scheme or an asym detail
        try:
            TPMT_PUBLIC._handle_scheme(scheme, templ)
        except RuntimeError as e:
            # nope try it as asymdetail
            symdetail = scheme

        TPMT_PUBLIC._handle_asymdetail(symdetail, templ)

        return templ

    @classmethod
    def from_pem(
        cls,
        data,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        symmetric=None,
        scheme=None,
        password=None,
    ):
        """Decode the public part from standard key encodings.

        Currently supports PEM, DER and SSH encoded public keys.

        Args:
            data (bytes): The encoded public key.
            nameAlg (int): The name algorithm for the public area, default is TPM2_ALG.SHA256.
            objectAttributes (int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            symmetric (TPMT_SYM_DEF_OBJECT, optional): The symmetric definition to use for the public area, default is None.
            scheme (TPMT_ASYM_SCHEME, optional): The signing/key exchange scheme to use for the public area, default is None.
            password (bytes, optional): The password used to decrypt the key, default is None.

        Returns:
            Returns a TPMT_PUBLIC instance.
        """
        p = cls()
        _public_from_encoding(data, p, password=password)
        p.nameAlg = nameAlg
        p.objectAttributes = objectAttributes
        if symmetric is None:
            p.parameters.asymDetail.symmetric.algorithm = TPM2_ALG.NULL
        else:
            p.parameters.asymDetail.symmetric = symmetric
        if scheme is None:
            p.parameters.asymDetail.scheme.scheme = TPM2_ALG.NULL
        else:
            p.parameters.asymDetail.scheme = scheme
        if p.type == TPM2_ALG.ECC:
            p.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
        return p

    def to_pem(self, encoding="pem"):
        """Encode the public key in standard format.

        Args:
            encoding (str, optional): The encoding format, one of "pem", "der" or "ssh".

        Returns:
            Returns the encoded key as bytes.
        """
        return _public_to_pem(self, encoding)

    def get_name(self):
        """Get the TPM name of the public area.

        Returns:
            Returns TPM2B_NAME.
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


class TPM2B_NAME(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_NV_PUBLIC(TPM_OBJECT):
    def get_name(self):
        """Get the TPM name of the NV public area.

        Returns:
            Returns TPM2B_NAME.
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
        data,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=(
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH
        ),
        symmetric=None,
        scheme=None,
        password=None,
    ):
        """Decode the public part from standard key encodings.

        Currently supports PEM, DER and SSH encoded public keys.

        Args:
            data (bytes): The encoded public key.
            nameAlg (int): The name algorithm for the public area, default is TPM2_ALG.SHA256.
            objectAttributes (int): The object attributes for the public area, default is (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH).
            symmetric (TPMT_SYM_DEF_OBJECT, optional): The symmetric definition to use for the public area, default is None.
            scheme (TPMT_ASYM_SCHEME, optional): The signing/key exchange shceme to use for the public area, default is None.
            password (bytes, optional): The password used to decrypt the key, default is None.

        Returns:
            Returns a TPM2B_PUBLIC instance.
        """
        pa = TPMT_PUBLIC.from_pem(
            data, nameAlg, objectAttributes, symmetric, scheme, password
        )
        p = cls(publicArea=pa)
        return p

    def to_pem(self, encoding="pem"):
        """Encode the public key in standard format.

        Args:
            encoding (str, optional): The encoding format, one of "pem", "der" or "ssh".

        Returns:
            Returns the encoded key as bytes.
        """
        return self.publicArea.to_pem(encoding)

    def get_name(self):
        """Get the TPM name of the public area.

        Returns:
            Returns TPM2B_NAME.
        """
        return self.publicArea.get_name()

    @classmethod
    def parse(
        cls,
        alg="rsa",
        objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS,
        nameAlg="sha256",
        authPolicy=None,
    ):

        return cls(TPMT_PUBLIC.parse(alg, objectAttributes, nameAlg, authPolicy))


class TPM2B_PUBLIC_KEY_RSA(TPM2B_SIMPLE_OBJECT):
    pass


class TPM2B_SENSITIVE(TPM_OBJECT):
    @classmethod
    def from_pem(cls, data, password=None):
        """Decode the private part from standard key encodings.

        Currently supports PEM, DER and SSH encoded private keys.

        Args:
            data (bytes): The encoded key as bytes.
            password (bytes, optional): The password used to decrypt the key, default is None.

        Returns:
            Returns an instance of TPM2B_SENSITIVE.
        """
        p = TPMT_SENSITIVE.from_pem(data, password)
        return cls(sensitiveArea=p)

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
            A tuple of of TPM2B_SENSITIVE and TPM2B_PUBLIC
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
            A tuple of TPM2B_SENSITIVE and TPM2B_PUBLIC
        """
        sa, pa = TPMT_SENSITIVE.symcipher_from_secret(
            secret, algorithm, mode, nameAlg, objectAttributes, seed
        )
        priv = TPM2B_SENSITIVE(sensitiveArea=sa)
        pub = TPM2B_PUBLIC(publicArea=pa)
        return (priv, pub)


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
    def parse(cls, algorithms):

        if algorithms is None or len(algorithms) == 0:
            return TPML_ALG()

        alglist = []
        for a in algorithms.split(","):
            a = a.strip()
            if len(a) > 0:
                alglist.append(TPM2_ALG.parse(a))

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
    def parse(selections):

        if selections is None or len(selections) == 0:
            return TPML_PCR_SELECTION()

        selectors = selections.split("+") if "+" in selections else [selections]

        if len(selectors) - 1 != selections.count("+"):
            raise RuntimeError(
                f"Malformed PCR bank selection list (unbalanced +), got: {selections}"
            )

        for x in selectors:
            if len(x) == 0:
                raise RuntimeError(
                    f"Malformed PCR bank selection list (unbalanced +), got: {selections}"
                )

        count = len(selectors)
        if count > lib.TPM2_NUM_PCR_BANKS:
            raise RuntimeError(
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
    def from_tools(cls, data):
        """Unmarshal tpm2-tools context.

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
    def get_name(self):
        """Get the TPM name of the NV public area.

        Returns:
            Returns TPM2B_NAME.
        """
        name = _getname(self)
        return TPM2B_NAME(name)


class TPMS_PCR_SELECT(TPM_OBJECT):
    pass


class TPMS_PCR_SELECTION(TPM_OBJECT):
    def __init__(self, halg=0, pcrs=None, _cdata=None):
        super().__init__(_cdata=_cdata)

        if not halg and not pcrs:
            return

        if bool(halg) != bool(pcrs):
            raise RuntimeError("halg and pcrs MUST be specified")

        self._cdata.hash = halg
        self._cdata.sizeofSelect = 3

        if pcrs == "all" or (len(pcrs) == 1 and pcrs[0] == "all"):
            self._cdata.pcrSelect[0] = 0xFF
            self._cdata.pcrSelect[1] = 0xFF
            self._cdata.pcrSelect[2] = 0xFF
            return

        for pcr in pcrs:
            if pcr < 0 or pcr > lib.TPM2_PCR_LAST:
                raise RuntimeError(f"PCR Index out of range, got {pcr}")
            self._cdata.pcrSelect[pcr // 8] |= 1 << (pcr % 8)

    @staticmethod
    def parse(selection):

        if selection is None or len(selection) == 0:
            return TPMS_PCR_SELECTION()

        hunks = [x.strip() for x in selection.split(":")]
        if len(hunks) != 2:
            raise RuntimeError(f"PCR Selection malformed, got {selection}")

        try:
            halg = int(hunks[0], 0)
        except ValueError:
            halg = TPM2_ALG.parse(hunks[0])

        if hunks[1] != "all":
            try:
                pcrs = [int(x.strip(), 0) for x in hunks[1].split(",")]
            except ValueError:
                raise RuntimeError(f"Expected PCR number, got {hunks[1]}")
        else:
            pcrs = hunks[1]

        return TPMS_PCR_SELECTION(halg=halg, pcrs=pcrs)


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


class TPMT_SYM_DEF_OBJECT(TPM_OBJECT):
    pass


class TPMT_KDF_SCHEME(TPM_OBJECT):
    pass


class TPMT_TK_CREATION(TPM_OBJECT):
    pass


class TPMT_ASYM_SCHEME(TPM_OBJECT):
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


class TPMU_SENSITIVE_COMPOSITE(TPM_OBJECT):
    pass


class TPMT_KEYEDHASH_SCHEME(TPM_OBJECT):
    pass


class TPMU_SCHEME_KEYEDHASH(TPM_OBJECT):
    pass


class TPMT_RSA_DECRYPT(TPM_OBJECT):
    pass


class TPMT_TK_HASHCHECK(TPM_OBJECT):
    pass


class TPMT_HA(TPM_OBJECT):
    def __bytes__(self):
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
