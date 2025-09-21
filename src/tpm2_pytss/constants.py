# SPDX-License-Identifier: BSD-2
""" This module contains all the constant values from the following TCG specifications:

- https://trustedcomputinggroup.org/resource/tpm-library-specification/. See Part 2 "Structures".
- https://trustedcomputinggroup.org/resource/tss-overview-common-structures-specification

Along with helpers to go from string values to constants and constant values to string values.
"""
from ._libtpm2_pytss import lib, ffi
from .internal.utils import (
    _CLASS_INT_ATTRS_from_string,
    _chkrc,
)
import weakref


class TPM_INT_MU:
    """Mixin class for marshaling/unmarshaling int types."""

    def marshal(self):
        """Marshal instance into bytes.

        Returns:
            Returns the marshaled type as bytes.
        """

        # use an alias name if set over the classname
        name = getattr(self, "_alias_name", self.__class__.__name__)
        mfunc = getattr(lib, f"Tss2_MU_{name}_Marshal", None)
        if mfunc is None:
            # default to scalar routines
            size = ffi.sizeof(f"{name}") * 8
            mfunc = getattr(lib, f"Tss2_MU_UINT{size}_Marshal", None)
            if mfunc is None:
                raise RuntimeError(
                    f"No marshal function found for {self.__class__.__name__}"
                )
        size = ffi.sizeof(f"{name}")
        offset = ffi.new("size_t *")
        buf = ffi.new(f"uint8_t[{size}]")
        _chkrc(mfunc(int(self), buf, size, offset))
        return bytes(buf[0 : offset[0]])

    @classmethod
    def unmarshal(cls, buf):
        """Unmarshal bytes into type instance.

        Args:
            buf (bytes): The bytes to be unmarshaled.

        Returns:
            Returns an instance of the current type and the number of bytes consumed.
        """

        # use an alias name if set over the classname
        name = getattr(cls, "_alias_name", cls.__name__)
        umfunc = getattr(lib, f"Tss2_MU_{name}_Unmarshal", None)
        if umfunc is None:
            # default to scalar routines
            size = ffi.sizeof(f"{name}") * 8
            umfunc = getattr(lib, f"Tss2_MU_UINT{size}_Unmarshal", None)
            if umfunc is None:
                raise RuntimeError(f"No unmarshal function found for {cls.__name__}")

        cdata = ffi.new(f"{name} *")
        offset = ffi.new("size_t *")
        _chkrc(umfunc(buf, len(buf), offset, cdata))
        return (cls(cdata[0]), offset[0])


class TPM_FRIENDLY_ITER(type):
    """Metaclass to make constants classes iterable"""

    def __iter__(cls):
        """Returns an iteratore over the constants in the class.

        Returns:
            (int): The int values of the constants in the class.

        Example:
            list(ESYS_TR) -> [4095, 255, 0, 1, 2, 3, ... ]
        """
        for value in cls._members_.values():
            yield value


class TPM_FRIENDLY_INT(int, TPM_INT_MU, metaclass=TPM_FRIENDLY_ITER):
    _FIXUP_MAP = {}

    @staticmethod
    def _get_members(cls) -> dict:
        """Finds all constants defined at class level."""
        members = dict()
        # Inherit constants from parent classes
        for sc in cls.__mro__[1:]:
            if not issubclass(sc, TPM_FRIENDLY_INT):
                break
            super_members = sc._get_members(sc)
            members.update(super_members)
        # Any class attribute that is an int and is not marked as private is a member
        for name, value in vars(cls).items():
            if not isinstance(value, int) or name.startswith("_"):
                continue
            members[name] = value
        return members

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        members = TPM_FRIENDLY_INT._get_members(cls)
        # Ensure that the members of the constant class have the class as the type
        for name, value in members.items():
            fixed_value = cls(value)
            members[name] = fixed_value
            setattr(cls, name, fixed_value)
        # Save the members so they can be used later
        cls._members_ = members

    @classmethod
    def parse(cls, value: str) -> int:
        # If it's a string initializer value, see if it matches anything in the list
        if isinstance(value, str):
            try:
                x = _CLASS_INT_ATTRS_from_string(cls, value, cls._FIXUP_MAP)
                if not isinstance(x, int):
                    raise KeyError(f'Expected int got: "{type(x)}"')
                return x
            except KeyError:
                raise ValueError(
                    f'Could not convert friendly name to value, got: "{value}"'
                )
        else:
            raise TypeError(f'Expected value to be a str object, got: "{type(value)}"')

    @classmethod
    def __contains__(cls, value: int) -> bool:
        """Indicates if a class contains a numeric constant.

        Args:
            value (int): The raw numerical number to test for.

        Returns:
            (bool): True if the class contains the constant, False otherwise.

        Example:
            7 in ESYS_TR -> True
        """
        return value in cls._members_.values()

    @classmethod
    def to_string(cls, value: int) -> str:
        """Converts an integer value into it's friendly string name for that class.

        Args:
            value (int): The raw numerical number to try and convert to a name.

        Returns:
            (str): The string of the constant defining the raw numeric.

        Raises:
            ValueError: If the numeric does not match a constant.

        Example:
            ESYS_TR.to_string(5) -> 'ESYS_TR.PCR5'
        """
        # Take the shortest match, ie OWNER over RH_OWNER.
        m = None
        items = vars(cls).items()
        for k, v in items:
            if v == value and (m is None or len(k) < len(m)):
                m = k

        if m is None:
            raise ValueError(f"Could not match {value} to class {cls.__name__}")

        return f"{cls.__name__}.{m}"

    def __str__(self) -> str:
        """Returns a string value of the constant normalized to lowercase.

        Returns:
            (str): a string value of the constant normalized to lowercase.

        Example:
            str(ESYS_TR.PCR2) -> 'pcr2'
        """
        for k, v in vars(self.__class__).items():
            if int(self) == v:
                return k.lower()
        return str(int(self))

    def __abs__(self):
        return self.__class__(int(self).__abs__())

    def __add__(self, value):
        return self.__class__(int(self).__add__(value))

    def __and__(self, value):
        return self.__class__(int(self).__and__(value))

    def __ceil__(self):
        return self.__class__(int(self).__ceil__())

    def __divmod__(self, value):
        a, b = int(self).__divmod__(value)
        return self.__class__(a), self.__class__(b)

    def __floor__(self):
        return self.__class__(int(self).__floor__())

    def __floordiv__(self, value):
        return self.__class__(int(self).__floordiv__(value))

    def __invert__(self):
        return self.__class__(int(self).__invert__())

    def __lshift__(self, value):
        return self.__class__(int(self).__lshift__(value))

    def __mod__(self, value):
        return self.__class__(int(self).__mod__(value))

    def __mul__(self, value):
        return self.__class__(int(self).__mul__(value))

    def __neg__(self):
        return self.__class__(int(self).__neg__())

    def __or__(self, value):
        return self.__class__(int(self).__or__(value))

    def __pos__(self):
        return self.__class__(int(self).__pos__())

    def __pow__(self, value, mod=None):
        return self.__class__(int(self).__pow__(value, mod))

    def __radd__(self, value):
        return self.__class__(int(self).__radd__(value))

    def __rand__(self, value):
        return self.__class__(int(self).__rand__(value))

    def __rdivmod__(self, value):
        a, b = int(self).__rdivmod__(value)
        return self.__class__(a), self.__class__(b)

    def __rfloordiv__(self, value):
        return self.__class__(int(self).__rfloordiv__(value))

    def __rlshift__(self, value):
        return self.__class__(int(self).__rlshift__(value))

    def __rmod__(self, value):
        return self.__class__(int(self).__rmod__(value))

    def __rmul__(self, value):
        return self.__class__(int(self).__rmul__(value))

    def __ror__(self, value):
        return self.__class__(int(self).__ror__(value))

    def __round__(self):
        return self.__class__(int(self).__round__())

    def __rpow__(self, value, mod=None):
        return self.__class__(int(self).__rpow__(value, mod))

    def __rrshift__(self, value):
        return self.__class__(int(self).__rrshift__(value))

    def __rshift__(self, value):
        return self.__class__(int(self).__rshift__(value))

    def __rsub__(self, value):
        return self.__class__(int(self).__rsub__(value))

    def __rtruediv__(self, value):
        return self.__class__(int(self).__rtruediv__(value))

    def __rxor__(self, value):
        return self.__class__(int(self).__rxor__(value))

    def __sub__(self, value):
        return self.__class__(int(self).__sub__(value))

    def __truediv__(self, value):
        return self.__class__(int(self).__truediv__(value))

    def __xor__(self, value):
        return self.__class__(int(self).__xor__(value))


class TPMA_FRIENDLY_INTLIST(TPM_FRIENDLY_INT):
    _MASKS = tuple()

    @classmethod
    def parse(cls, value: str) -> int:
        """Converts a string of | separated constant values into it's integer value.

        Given a pipe "|" separated list of string constant values that represent the
        bitwise values returns the value itself. The value "" (empty string) returns
        a 0.

        Args:
            value (str): The string "bitwise" expression of the object or the empty string.

        Returns:
            The integer result.

        Raises:
            TypeError: If the value is not a str.
            ValueError: If a field portion of the str does not match a constant.

        Examples:
            TPMA_NV.parse("ppwrite|orderly|NO_DA") -> 0x6000001
            TPMA_NV.parse("NO_DA") -> 0x2000000
        """

        intvalue = 0

        if not isinstance(value, str):
            raise TypeError(f'Expected value to be a str, got: "{type(value)}"')

        hunks = value.split("|") if "|" in value else [value]
        for k in list(hunks):
            if "=" not in k:
                continue
            hname, hval = k.split("=", 1)
            v = int(hval, base=0)
            hunks.remove(k)
            found = False
            for mask, shift, name in cls._MASKS:
                if hname != name:
                    continue
                mv = mask >> shift
                if v > mv:
                    raise ValueError(
                        f"value for {name} is to large, got 0x{v:x}, max is 0x{mv:x}"
                    )
                intvalue = intvalue | (v << shift)
                found = True
                break
            if not found:
                raise ValueError(f"unknown mask type {hname}")
        for k in hunks:
            try:
                intvalue |= _CLASS_INT_ATTRS_from_string(cls, k, cls._FIXUP_MAP)
            except KeyError:
                raise ValueError(
                    f'Could not convert friendly name to value, got: "{k}"'
                )

        return intvalue

    def __str__(self):
        """Given a constant, return the string bitwise representation.

        Each constant is seperated by the "|" (pipe) character.

        Returns:
            (str): a bitwise string value of the fields for the constant normalized to lowercase.

        Raises:
            ValueError: If their are unmatched bits in the constant value.

        Example:
            str(TPMA_NV(TPMA_NV.PPWRITE|TPMA_NV.ORDERLY|TPMA_NV.NO_DA)) -> 'ppwrite|noda|orderly'
        """
        cv = int(self)
        ints = list()
        for k, v in vars(self.__class__).items():
            if cv == 0:
                break
            if (
                not isinstance(v, int)
                or k.startswith(("_", "_DEFAULT"))
                or k.endswith(("_MASK", "_SHIFT"))
            ):
                continue
            for fk, fv in self._FIXUP_MAP.items():
                if k == fv:
                    k = fk
                    break
            if v == 0 or v & cv != v:
                continue
            ints.append(k.lower())
            cv = cv ^ v
        for mask, shift, name in self._MASKS:
            if not cv & mask:
                continue
            v = (cv & mask) >> shift
            s = f"{name}=0x{v:x}"
            cv = cv ^ (cv & mask)
            ints.append(s)
        if cv:
            raise ValueError(f"unnmatched values left: 0x{cv:x}")
        return "|".join(ints)


class TPM2_MAX(TPM_FRIENDLY_INT):
    DIGEST_BUFFER = 1024
    NV_BUFFER_SIZE = 2048
    PCRS = 32
    ALG_LIST_SIZE = 128
    CAP_CC = 256
    CAP_BUFFER = 1024
    CONTEXT_SIZE = 5120


class ESYS_TR(TPM_FRIENDLY_INT):
    """ESYS_TR is an ESAPI identifier representing a TPM resource

    To get the ESYS_TR identifier for a persistent handle, such as a NV area
    or a persistent key use :func:`tpm2_pytss.ESAPI.tr_from_tpmpublic`

    Can be used as a context manager to flush transient and session handles.
    """

    NONE = 0xFFF
    PASSWORD = 0x0FF
    PCR0 = 0
    PCR1 = 1
    PCR2 = 2
    PCR3 = 3
    PCR4 = 4
    PCR5 = 5
    PCR6 = 6
    PCR7 = 7
    PCR8 = 8
    PCR9 = 9
    PCR10 = 10
    PCR11 = 11
    PCR12 = 12
    PCR13 = 13
    PCR14 = 14
    PCR15 = 15
    PCR16 = 16
    PCR17 = 17
    PCR18 = 18
    PCR19 = 19
    PCR20 = 20
    PCR21 = 21
    PCR22 = 22
    PCR23 = 23
    PCR24 = 24
    PCR25 = 25
    PCR26 = 26
    PCR27 = 27
    PCR28 = 28
    PCR29 = 29
    PCR30 = 30
    PCR31 = 31
    OWNER = 0x101
    NULL = 0x107
    LOCKOUT = 0x10A
    ENDORSEMENT = 0x10B
    PLATFORM = 0x10C
    PLATFORM_NV = 0x10D
    RH_OWNER = 0x101
    RH_NULL = 0x107
    RH_LOCKOUT = 0x10A
    RH_ENDORSEMENT = 0x10B
    RH_PLATFORM = 0x10C
    RH_PLATFORM_NV = 0x10D
    RH_FW_OWNER = 0x10E
    RH_FW_ENDORSEMENT = 0x10F
    RH_FW_PLATFORM = 0x110
    RH_FW_NULL = 0x111
    RH_SVN_OWNER_BASE = 0x1010000
    RH_SVN_ENDORSEMENT_BASE = 0x1020000
    RH_SVN_PLATFORM_BASE = 0x1030000
    RH_SVN_NULL_BASE = 0x1040000
    RH_ACT_0 = 0x120
    RH_ACT_1 = 0x121
    RH_ACT_2 = 0x122
    RH_ACT_3 = 0x123
    RH_ACT_4 = 0x124
    RH_ACT_5 = 0x125
    RH_ACT_6 = 0x126
    RH_ACT_7 = 0x127
    RH_ACT_8 = 0x128
    RH_ACT_9 = 0x129
    RH_ACT_A = 0x12A
    RH_ACT_B = 0x12B
    RH_ACT_C = 0x12C
    RH_ACT_D = 0x12D
    RH_ACT_E = 0x12E
    RH_ACT_F = 0x12F

    def __new__(cls, value: int, ectx: "ESAPI" = None):
        obj = super().__new__(cls, value)
        if ectx is not None and not ectx.is_closed():
            obj._ectx_ref = weakref.ref(ectx)
        else:
            obj._ectx_ref = None
        return obj

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self._ectx_ref is None:
            return False
        ectx = self._ectx_ref()
        if ectx is None or ectx.is_closed():
            return False
        handle = ectx.tr_get_tpm_handle(self)
        if (handle & TPM2_HR.RANGE_MASK) in (
            TPM2_HR.TRANSIENT,
            TPM2_HR.HMAC_SESSION,
            TPM2_HR.POLICY_SESSION,
        ):
            ectx.flush_context(self)
        self._ectx_ref = None
        return False

    def marshal(self):
        raise NotImplementedError("Use serialize() instead")

    @classmethod
    def unmarshal(cls, buf):
        raise NotImplementedError("Use deserialize() instead")

    def serialize(self, ectx: "ESAPI") -> bytes:
        """Same as see tpm2_pytss.ESAPI.tr_serialize

        Args:
            ectx(ESAPI): The esapi context the ESYS_TR was created
            from.

        Returns:
            A byte array of the serialized ESYS_TR.
        """
        return ectx.tr_serialize(self)

    @staticmethod
    def deserialize(ectx: "ESAPI", buffer: bytes) -> "ESYS_TR":
        """Same as see tpm2_pytss.ESAPI.tr_derialize

        Args:
            ectx(ESAPI): The esapi context to load the ESYS_TR on.

        Returns:
            An ESYS_TR representing the TPM object.
        """

        return ectx.tr_deserialize(buffer)

    def get_name(self, ectx: "ESAPI") -> "TPM2B_NAME":
        """Same as see tpm2_pytss.ESAPI.tr_get_name

        Args:
            ectx(ESAPI): The esapi context to retrieve the object name from.

        Returns:
            A TPM2B_NAME object.
        """
        return ectx.tr_get_name(self)

    def close(self, ectx: "ESAPI"):
        """Same as see tpm2_pytss.ESAPI.tr_close

        Args:
            ectx(ESAPI): The esapi context to close the ESYS_TR on.
        """
        return ectx.tr_close(self)

    @staticmethod
    def parts_to_blob(handle: "TPM2_HANDLE", public: "TPM2B_PUBLIC") -> bytes:
        """Converts a persistent handle and public to a serialized ESYS_TR.

        Args:
            handle(TPM2_HANDLE): The PERSISTENT handle to convert.
            public(TPM2B_PUBLIC): The corresponding public for the handle.

        Returns:
            A SERIALIZED ESYS_TR that can be used with ESYS_TR.deserialize later.
        """

        if (handle >> TPM2_HR.SHIFT) != TPM2_HT.PERSISTENT:
            raise ValueError("Expected a persistent handle, got: {handle:#x}")

        b = bytearray()
        b.extend(handle.to_bytes(4, byteorder="big"))
        b.extend(public.get_name().marshal())
        b.extend(int(1).to_bytes(4, byteorder="big"))
        b.extend(public.marshal())
        return bytes(b)


class TPM2_RH(TPM_FRIENDLY_INT):
    FIRST = 0x40000000
    SRK = 0x40000000
    OWNER = 0x40000001
    REVOKE = 0x40000002
    TRANSPORT = 0x40000003
    OPERATOR = 0x40000004
    ADMIN = 0x40000005
    EK = 0x40000006
    NULL = 0x40000007
    UNASSIGNED = 0x40000008
    PW = 0x40000009
    LOCKOUT = 0x4000000A
    ENDORSEMENT = 0x4000000B
    PLATFORM = 0x4000000C
    PLATFORM_NV = 0x4000000D
    FW_OWNER = 0x40000140
    FW_ENDORSEMENT = 0x40000141
    FW_PLATFORM = 0x40000142
    FW_NULL = 0x40000143
    SVN_OWNER_BASE = 0x40010000
    SVN_ENDORSEMENT_BASE = 0x40020000
    SVN_PLATFORM_BASE = 0x40030000
    SVN_NULL_BASE = 0x40040000
    ACT_0 = 0x40000110
    ACT_1 = 0x40000111
    ACT_2 = 0x40000112
    ACT_3 = 0x40000113
    ACT_4 = 0x40000114
    ACT_5 = 0x40000115
    ACT_6 = 0x40000116
    ACT_7 = 0x40000117
    ACT_8 = 0x40000118
    ACT_9 = 0x40000119
    ACT_A = 0x4000011A
    ACT_B = 0x4000011B
    ACT_C = 0x4000011C
    ACT_D = 0x4000011D
    ACT_E = 0x4000011E
    ACT_F = 0x4000011F
    LAST = 0x4004FFFF


class TPM2_ALG(TPM_FRIENDLY_INT):
    _alias_name = "TPM2_ALG_ID"
    ERROR = 0x0000
    RSA = 0x0001
    TDES = 0x0003
    SHA = 0x0004
    SHA1 = 0x0004
    HMAC = 0x0005
    AES = 0x0006
    MGF1 = 0x0007
    KEYEDHASH = 0x0008
    XOR = 0x000A
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D
    NULL = 0x0010
    SM3_256 = 0x0012
    SM4 = 0x0013
    RSASSA = 0x0014
    RSAES = 0x0015
    RSAPSS = 0x0016
    OAEP = 0x0017
    ECDSA = 0x0018
    ECDH = 0x0019
    ECDAA = 0x001A
    SM2 = 0x001B
    ECSCHNORR = 0x001C
    ECMQV = 0x001D
    KDF1_SP800_56A = 0x0020
    KDF2 = 0x0021
    KDF1_SP800_108 = 0x0022
    ECC = 0x0023
    SYMCIPHER = 0x0025
    CAMELLIA = 0x0026
    CTR = 0x0040
    SHA3_256 = 0x0027
    SHA3_384 = 0x0028
    SHA3_512 = 0x0029
    OFB = 0x0041
    CBC = 0x0042
    CFB = 0x0043
    ECB = 0x0044
    FIRST = 0x0001
    LAST = 0x0044


class TPM2_ALG_ID(TPM2_ALG):
    pass


class TPM2_ECC(TPM_FRIENDLY_INT):
    NONE = 0x0000
    NIST_P192 = 0x0001
    NIST_P224 = 0x0002
    NIST_P256 = 0x0003
    NIST_P384 = 0x0004
    NIST_P521 = 0x0005
    BN_P256 = 0x0010
    BN_P638 = 0x0011
    SM2_P256 = 0x0020

    _FIXUP_MAP = {
        "192": "NIST_P192",
        "224": "NIST_P224",
        "256": "NIST_P256",
        "384": "NIST_P384",
        "521": "NIST_P521",
        "SM2": "SM2_P256",
    }


class TPM2_ECC_CURVE(TPM2_ECC):
    pass


class TPM2_CC(TPM_FRIENDLY_INT):
    NV_UndefineSpaceSpecial = 0x0000011F
    FIRST = 0x0000011F
    EvictControl = 0x00000120
    HierarchyControl = 0x00000121
    NV_UndefineSpace = 0x00000122
    ChangeEPS = 0x00000124
    ChangePPS = 0x00000125
    Clear = 0x00000126
    ClearControl = 0x00000127
    ClockSet = 0x00000128
    HierarchyChangeAuth = 0x00000129
    NV_DefineSpace = 0x0000012A
    PCR_Allocate = 0x0000012B
    PCR_SetAuthPolicy = 0x0000012C
    PP_Commands = 0x0000012D
    SetPrimaryPolicy = 0x0000012E
    FieldUpgradeStart = 0x0000012F
    ClockRateAdjust = 0x00000130
    CreatePrimary = 0x00000131
    NV_GlobalWriteLock = 0x00000132
    GetCommandAuditDigest = 0x00000133
    NV_Increment = 0x00000134
    NV_SetBits = 0x00000135
    NV_Extend = 0x00000136
    NV_Write = 0x00000137
    NV_WriteLock = 0x00000138
    DictionaryAttackLockReset = 0x00000139
    DictionaryAttackParameters = 0x0000013A
    NV_ChangeAuth = 0x0000013B
    PCR_Event = 0x0000013C
    PCR_Reset = 0x0000013D
    SequenceComplete = 0x0000013E
    SetAlgorithmSet = 0x0000013F
    SetCommandCodeAuditStatus = 0x00000140
    FieldUpgradeData = 0x00000141
    IncrementalSelfTest = 0x00000142
    SelfTest = 0x00000143
    Startup = 0x00000144
    Shutdown = 0x00000145
    StirRandom = 0x00000146
    ActivateCredential = 0x00000147
    Certify = 0x00000148
    PolicyNV = 0x00000149
    CertifyCreation = 0x0000014A
    Duplicate = 0x0000014B
    GetTime = 0x0000014C
    GetSessionAuditDigest = 0x0000014D
    NV_Read = 0x0000014E
    NV_ReadLock = 0x0000014F
    ObjectChangeAuth = 0x00000150
    PolicySecret = 0x00000151
    Rewrap = 0x00000152
    Create = 0x00000153
    ECDH_ZGen = 0x00000154
    HMAC = 0x00000155
    MAC = 0x00000155
    Import = 0x00000156
    Load = 0x00000157
    Quote = 0x00000158
    RSA_Decrypt = 0x00000159
    HMAC_Start = 0x0000015B
    MAC_Start = 0x0000015B
    SequenceUpdate = 0x0000015C
    Sign = 0x0000015D
    Unseal = 0x0000015E
    PolicySigned = 0x00000160
    ContextLoad = 0x00000161
    ContextSave = 0x00000162
    ECDH_KeyGen = 0x00000163
    EncryptDecrypt = 0x00000164
    FlushContext = 0x00000165
    LoadExternal = 0x00000167
    MakeCredential = 0x00000168
    NV_ReadPublic = 0x00000169
    PolicyAuthorize = 0x0000016A
    PolicyAuthValue = 0x0000016B
    PolicyCommandCode = 0x0000016C
    PolicyCounterTimer = 0x0000016D
    PolicyCpHash = 0x0000016E
    PolicyLocality = 0x0000016F
    PolicyNameHash = 0x00000170
    PolicyOR = 0x00000171
    PolicyTicket = 0x00000172
    ReadPublic = 0x00000173
    RSA_Encrypt = 0x00000174
    StartAuthSession = 0x00000176
    VerifySignature = 0x00000177
    ECC_Parameters = 0x00000178
    FirmwareRead = 0x00000179
    GetCapability = 0x0000017A
    GetRandom = 0x0000017B
    GetTestResult = 0x0000017C
    Hash = 0x0000017D
    PCR_Read = 0x0000017E
    PolicyPCR = 0x0000017F
    PolicyRestart = 0x00000180
    ReadClock = 0x00000181
    PCR_Extend = 0x00000182
    PCR_SetAuthValue = 0x00000183
    NV_Certify = 0x00000184
    EventSequenceComplete = 0x00000185
    HashSequenceStart = 0x00000186
    PolicyPhysicalPresence = 0x00000187
    PolicyDuplicationSelect = 0x00000188
    PolicyGetDigest = 0x00000189
    TestParms = 0x0000018A
    Commit = 0x0000018B
    PolicyPassword = 0x0000018C
    ZGen_2Phase = 0x0000018D
    EC_Ephemeral = 0x0000018E
    PolicyNvWritten = 0x0000018F
    PolicyTemplate = 0x00000190
    CreateLoaded = 0x00000191
    PolicyAuthorizeNV = 0x00000192
    EncryptDecrypt2 = 0x00000193
    AC_GetCapability = 0x00000194
    AC_Send = 0x00000195
    Policy_AC_SendSelect = 0x00000196
    CertifyX509 = 0x00000197
    ACT_SetTimeout = 0x00000198
    ECC_Encrypt = 0x00000199
    ECC_Decrypt = 0x0000019A
    PolicyCapability = 0x0000019B
    PolicyParameters = 0x0000019C
    LAST = 0x0000019C
    Vendor_TCG_Test = 0x20000000


class TPM2_SPEC(TPM_FRIENDLY_INT):
    FAMILY = 0x322E3000
    LEVEL = 00
    VERSION = 159
    YEAR = 2019
    DAY_OF_YEAR = 312


class TPM2_GENERATED(TPM_FRIENDLY_INT):
    VALUE = 0xFF544347


class TPM_BASE_RC(TPM_FRIENDLY_INT):
    def decode(self):
        return ffi.string(lib.Tss2_RC_Decode(self)).decode()


class TPM2_RC(TPM_BASE_RC):
    SUCCESS = 0x000
    BAD_TAG = 0x01E
    VER1 = 0x100
    INITIALIZE = VER1 + 0x000
    FAILURE = VER1 + 0x001
    SEQUENCE = VER1 + 0x003
    PRIVATE = VER1 + 0x00B
    HMAC = VER1 + 0x019
    DISABLED = VER1 + 0x020
    EXCLUSIVE = VER1 + 0x021
    AUTH_TYPE = VER1 + 0x024
    AUTH_MISSING = VER1 + 0x025
    POLICY = VER1 + 0x026
    PCR = VER1 + 0x027
    PCR_CHANGED = VER1 + 0x028
    UPGRADE = VER1 + 0x02D
    TOO_MANY_CONTEXTS = VER1 + 0x02E
    AUTH_UNAVAILABLE = VER1 + 0x02F
    REBOOT = VER1 + 0x030
    UNBALANCED = VER1 + 0x031
    COMMAND_SIZE = VER1 + 0x042
    COMMAND_CODE = VER1 + 0x043
    AUTHSIZE = VER1 + 0x044
    AUTH_CONTEXT = VER1 + 0x045
    NV_RANGE = VER1 + 0x046
    NV_SIZE = VER1 + 0x047
    NV_LOCKED = VER1 + 0x048
    NV_AUTHORIZATION = VER1 + 0x049
    NV_UNINITIALIZED = VER1 + 0x04A
    NV_SPACE = VER1 + 0x04B
    NV_DEFINED = VER1 + 0x04C
    BAD_CONTEXT = VER1 + 0x050
    CPHASH = VER1 + 0x051
    PARENT = VER1 + 0x052
    NEEDS_TEST = VER1 + 0x053
    NO_RESULT = VER1 + 0x054
    SENSITIVE = VER1 + 0x055
    MAX_FM0 = VER1 + 0x07F
    FMT1 = 0x080
    ASYMMETRIC = FMT1 + 0x001
    ATTRIBUTES = FMT1 + 0x002
    HASH = FMT1 + 0x003
    VALUE = FMT1 + 0x004
    HIERARCHY = FMT1 + 0x005
    KEY_SIZE = FMT1 + 0x007
    MGF = FMT1 + 0x008
    MODE = FMT1 + 0x009
    TYPE = FMT1 + 0x00A
    HANDLE = FMT1 + 0x00B
    KDF = FMT1 + 0x00C
    RANGE = FMT1 + 0x00D
    AUTH_FAIL = FMT1 + 0x00E
    NONCE = FMT1 + 0x00F
    PP = FMT1 + 0x010
    SCHEME = FMT1 + 0x012
    SIZE = FMT1 + 0x015
    SYMMETRIC = FMT1 + 0x016
    TAG = FMT1 + 0x017
    SELECTOR = FMT1 + 0x018
    INSUFFICIENT = FMT1 + 0x01A
    SIGNATURE = FMT1 + 0x01B
    KEY = FMT1 + 0x01C
    POLICY_FAIL = FMT1 + 0x01D
    INTEGRITY = FMT1 + 0x01F
    TICKET = FMT1 + 0x020
    BAD_AUTH = FMT1 + 0x022
    EXPIRED = FMT1 + 0x023
    POLICY_CC = FMT1 + 0x024
    BINDING = FMT1 + 0x025
    CURVE = FMT1 + 0x026
    ECC_POINT = FMT1 + 0x027
    FW_LIMITED = FMT1 + 0x028
    SVN_LIMITED = FMT1 + 0x029
    WARN = 0x900
    CONTEXT_GAP = WARN + 0x001
    OBJECT_MEMORY = WARN + 0x002
    SESSION_MEMORY = WARN + 0x003
    MEMORY = WARN + 0x004
    SESSION_HANDLES = WARN + 0x005
    OBJECT_HANDLES = WARN + 0x006
    LOCALITY = WARN + 0x007
    YIELDED = WARN + 0x008
    CANCELED = WARN + 0x009
    TESTING = WARN + 0x00A
    REFERENCE_H0 = WARN + 0x010
    REFERENCE_H1 = WARN + 0x011
    REFERENCE_H2 = WARN + 0x012
    REFERENCE_H3 = WARN + 0x013
    REFERENCE_H4 = WARN + 0x014
    REFERENCE_H5 = WARN + 0x015
    REFERENCE_H6 = WARN + 0x016
    REFERENCE_S0 = WARN + 0x018
    REFERENCE_S1 = WARN + 0x019
    REFERENCE_S2 = WARN + 0x01A
    REFERENCE_S3 = WARN + 0x01B
    REFERENCE_S4 = WARN + 0x01C
    REFERENCE_S5 = WARN + 0x01D
    REFERENCE_S6 = WARN + 0x01E
    NV_RATE = WARN + 0x020
    LOCKOUT = WARN + 0x021
    RETRY = WARN + 0x022
    NV_UNAVAILABLE = WARN + 0x023
    NOT_USED = WARN + 0x07F
    H = 0x000
    P = 0x040
    S = 0x800
    RC1 = 0x100
    RC2 = 0x200
    RC3 = 0x300
    RC4 = 0x400
    RC5 = 0x500
    RC6 = 0x600
    RC7 = 0x700
    RC8 = 0x800
    RC9 = 0x900
    A = 0xA00
    B = 0xB00
    C = 0xC00
    D = 0xD00
    E = 0xE00
    F = 0xF00
    N_MASK = 0xF00


class TSS2_RC(TPM_BASE_RC):
    RC_LAYER_SHIFT = 16
    RC_LAYER_MASK = 0xFF << RC_LAYER_SHIFT
    TPM_RC_LAYER = 0 << RC_LAYER_SHIFT
    FEATURE_RC_LAYER = 6 << RC_LAYER_SHIFT
    ESAPI_RC_LAYER = 7 << RC_LAYER_SHIFT
    SYS_RC_LAYER = 8 << RC_LAYER_SHIFT
    MU_RC_LAYER = 9 << RC_LAYER_SHIFT
    TCTI_RC_LAYER = 10 << RC_LAYER_SHIFT
    RESMGR_RC_LAYER = 11 << RC_LAYER_SHIFT
    RESMGR_TPM_RC_LAYER = 12 << RC_LAYER_SHIFT
    POLICY_RC_LAYER = 13 << RC_LAYER_SHIFT
    BASE_RC_GENERAL_FAILURE = 1
    BASE_RC_NOT_IMPLEMENTED = 2
    BASE_RC_BAD_CONTEXT = 3
    BASE_RC_ABI_MISMATCH = 4
    BASE_RC_BAD_REFERENCE = 5
    BASE_RC_INSUFFICIENT_BUFFER = 6
    BASE_RC_BAD_SEQUENCE = 7
    BASE_RC_NO_CONNECTION = 8
    BASE_RC_TRY_AGAIN = 9
    BASE_RC_IO_ERROR = 10
    BASE_RC_BAD_VALUE = 11
    BASE_RC_NOT_PERMITTED = 12
    BASE_RC_INVALID_SESSIONS = 13
    BASE_RC_NO_DECRYPT_PARAM = 14
    BASE_RC_NO_ENCRYPT_PARAM = 15
    BASE_RC_BAD_SIZE = 16
    BASE_RC_MALFORMED_RESPONSE = 17
    BASE_RC_INSUFFICIENT_CONTEXT = 18
    BASE_RC_INSUFFICIENT_RESPONSE = 19
    BASE_RC_INCOMPATIBLE_TCTI = 20
    BASE_RC_NOT_SUPPORTED = 21
    BASE_RC_BAD_TCTI_STRUCTURE = 22
    BASE_RC_MEMORY = 23
    BASE_RC_BAD_TR = 24
    BASE_RC_MULTIPLE_DECRYPT_SESSIONS = 25
    BASE_RC_MULTIPLE_ENCRYPT_SESSIONS = 26
    BASE_RC_RSP_AUTH_FAILED = 27
    BASE_RC_NO_CONFIG = 28
    BASE_RC_BAD_PATH = 29
    BASE_RC_NOT_DELETABLE = 30
    BASE_RC_PATH_ALREADY_EXISTS = 31
    BASE_RC_KEY_NOT_FOUND = 32
    BASE_RC_SIGNATURE_VERIFICATION_FAILED = 33
    BASE_RC_HASH_MISMATCH = 34
    BASE_RC_KEY_NOT_DUPLICABLE = 35
    BASE_RC_PATH_NOT_FOUND = 36
    BASE_RC_NO_CERT = 37
    BASE_RC_NO_PCR = 38
    BASE_RC_PCR_NOT_RESETTABLE = 39
    BASE_RC_BAD_TEMPLATE = 40
    BASE_RC_AUTHORIZATION_FAILED = 41
    BASE_RC_AUTHORIZATION_UNKNOWN = 42
    BASE_RC_NV_NOT_READABLE = 43
    BASE_RC_NV_TOO_SMALL = 44
    BASE_RC_NV_NOT_WRITEABLE = 45
    BASE_RC_POLICY_UNKNOWN = 46
    BASE_RC_NV_WRONG_TYPE = 47
    BASE_RC_NAME_ALREADY_EXISTS = 48
    BASE_RC_NO_TPM = 49
    BASE_RC_BAD_KEY = 50
    BASE_RC_NO_HANDLE = 51
    BASE_RC_NOT_PROVISIONED = 52
    BASE_RC_ALREADY_PROVISIONED = 53
    BASE_RC_CALLBACK_NULL = 54
    LAYER_IMPLEMENTATION_SPECIFIC_OFFSET = 0xF800
    LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT = 11
    RC_SUCCESS = 0
    TCTI_RC_GENERAL_FAILURE = TCTI_RC_LAYER | BASE_RC_GENERAL_FAILURE
    TCTI_RC_NOT_IMPLEMENTED = TCTI_RC_LAYER | BASE_RC_NOT_IMPLEMENTED
    TCTI_RC_BAD_CONTEXT = TCTI_RC_LAYER | BASE_RC_BAD_CONTEXT
    TCTI_RC_ABI_MISMATCH = TCTI_RC_LAYER | BASE_RC_ABI_MISMATCH
    TCTI_RC_BAD_REFERENCE = TCTI_RC_LAYER | BASE_RC_BAD_REFERENCE
    TCTI_RC_INSUFFICIENT_BUFFER = TCTI_RC_LAYER | BASE_RC_INSUFFICIENT_BUFFER
    TCTI_RC_BAD_SEQUENCE = TCTI_RC_LAYER | BASE_RC_BAD_SEQUENCE
    TCTI_RC_NO_CONNECTION = TCTI_RC_LAYER | BASE_RC_NO_CONNECTION
    TCTI_RC_TRY_AGAIN = TCTI_RC_LAYER | BASE_RC_TRY_AGAIN
    TCTI_RC_IO_ERROR = TCTI_RC_LAYER | BASE_RC_IO_ERROR
    TCTI_RC_BAD_VALUE = TCTI_RC_LAYER | BASE_RC_BAD_VALUE
    TCTI_RC_NOT_PERMITTED = TCTI_RC_LAYER | BASE_RC_NOT_PERMITTED
    TCTI_RC_MALFORMED_RESPONSE = TCTI_RC_LAYER | BASE_RC_MALFORMED_RESPONSE
    TCTI_RC_NOT_SUPPORTED = TCTI_RC_LAYER | BASE_RC_NOT_SUPPORTED
    TCTI_RC_MEMORY = TCTI_RC_LAYER | BASE_RC_MEMORY
    SYS_RC_GENERAL_FAILURE = SYS_RC_LAYER | BASE_RC_GENERAL_FAILURE
    SYS_RC_ABI_MISMATCH = SYS_RC_LAYER | BASE_RC_ABI_MISMATCH
    SYS_RC_BAD_REFERENCE = SYS_RC_LAYER | BASE_RC_BAD_REFERENCE
    SYS_RC_INSUFFICIENT_BUFFER = SYS_RC_LAYER | BASE_RC_INSUFFICIENT_BUFFER
    SYS_RC_BAD_SEQUENCE = SYS_RC_LAYER | BASE_RC_BAD_SEQUENCE
    SYS_RC_BAD_VALUE = SYS_RC_LAYER | BASE_RC_BAD_VALUE
    SYS_RC_INVALID_SESSIONS = SYS_RC_LAYER | BASE_RC_INVALID_SESSIONS
    SYS_RC_NO_DECRYPT_PARAM = SYS_RC_LAYER | BASE_RC_NO_DECRYPT_PARAM
    SYS_RC_NO_ENCRYPT_PARAM = SYS_RC_LAYER | BASE_RC_NO_ENCRYPT_PARAM
    SYS_RC_BAD_SIZE = SYS_RC_LAYER | BASE_RC_BAD_SIZE
    SYS_RC_MALFORMED_RESPONSE = SYS_RC_LAYER | BASE_RC_MALFORMED_RESPONSE
    SYS_RC_INSUFFICIENT_CONTEXT = SYS_RC_LAYER | BASE_RC_INSUFFICIENT_CONTEXT
    SYS_RC_INSUFFICIENT_RESPONSE = SYS_RC_LAYER | BASE_RC_INSUFFICIENT_RESPONSE
    SYS_RC_INCOMPATIBLE_TCTI = SYS_RC_LAYER | BASE_RC_INCOMPATIBLE_TCTI
    SYS_RC_BAD_TCTI_STRUCTURE = SYS_RC_LAYER | BASE_RC_BAD_TCTI_STRUCTURE
    MU_RC_GENERAL_FAILURE = MU_RC_LAYER | BASE_RC_GENERAL_FAILURE
    MU_RC_BAD_REFERENCE = MU_RC_LAYER | BASE_RC_BAD_REFERENCE
    MU_RC_BAD_SIZE = MU_RC_LAYER | BASE_RC_BAD_SIZE
    MU_RC_BAD_VALUE = MU_RC_LAYER | BASE_RC_BAD_VALUE
    MU_RC_INSUFFICIENT_BUFFER = MU_RC_LAYER | BASE_RC_INSUFFICIENT_BUFFER
    ESYS_RC_GENERAL_FAILURE = ESAPI_RC_LAYER | BASE_RC_GENERAL_FAILURE
    ESYS_RC_NOT_IMPLEMENTED = ESAPI_RC_LAYER | BASE_RC_NOT_IMPLEMENTED
    ESYS_RC_ABI_MISMATCH = ESAPI_RC_LAYER | BASE_RC_ABI_MISMATCH
    ESYS_RC_BAD_REFERENCE = ESAPI_RC_LAYER | BASE_RC_BAD_REFERENCE
    ESYS_RC_INSUFFICIENT_BUFFER = ESAPI_RC_LAYER | BASE_RC_INSUFFICIENT_BUFFER
    ESYS_RC_BAD_SEQUENCE = ESAPI_RC_LAYER | BASE_RC_BAD_SEQUENCE
    ESYS_RC_INVALID_SESSIONS = ESAPI_RC_LAYER | BASE_RC_INVALID_SESSIONS
    ESYS_RC_TRY_AGAIN = ESAPI_RC_LAYER | BASE_RC_TRY_AGAIN
    ESYS_RC_IO_ERROR = ESAPI_RC_LAYER | BASE_RC_IO_ERROR
    ESYS_RC_BAD_VALUE = ESAPI_RC_LAYER | BASE_RC_BAD_VALUE
    ESYS_RC_NO_DECRYPT_PARAM = ESAPI_RC_LAYER | BASE_RC_NO_DECRYPT_PARAM
    ESYS_RC_NO_ENCRYPT_PARAM = ESAPI_RC_LAYER | BASE_RC_NO_ENCRYPT_PARAM
    ESYS_RC_BAD_SIZE = ESAPI_RC_LAYER | BASE_RC_BAD_SIZE
    ESYS_RC_MALFORMED_RESPONSE = ESAPI_RC_LAYER | BASE_RC_MALFORMED_RESPONSE
    ESYS_RC_INSUFFICIENT_CONTEXT = ESAPI_RC_LAYER | BASE_RC_INSUFFICIENT_CONTEXT
    ESYS_RC_INSUFFICIENT_RESPONSE = ESAPI_RC_LAYER | BASE_RC_INSUFFICIENT_RESPONSE
    ESYS_RC_INCOMPATIBLE_TCTI = ESAPI_RC_LAYER | BASE_RC_INCOMPATIBLE_TCTI
    ESYS_RC_BAD_TCTI_STRUCTURE = ESAPI_RC_LAYER | BASE_RC_BAD_TCTI_STRUCTURE
    ESYS_RC_MEMORY = ESAPI_RC_LAYER | BASE_RC_MEMORY
    ESYS_RC_BAD_TR = ESAPI_RC_LAYER | BASE_RC_BAD_TR
    ESYS_RC_MULTIPLE_DECRYPT_SESSIONS = (
        ESAPI_RC_LAYER | BASE_RC_MULTIPLE_DECRYPT_SESSIONS
    )
    ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS = (
        ESAPI_RC_LAYER | BASE_RC_MULTIPLE_ENCRYPT_SESSIONS
    )
    ESYS_RC_RSP_AUTH_FAILED = ESAPI_RC_LAYER | BASE_RC_RSP_AUTH_FAILED
    FAPI_RC_GENERAL_FAILURE = FEATURE_RC_LAYER | BASE_RC_GENERAL_FAILURE
    FAPI_RC_NOT_IMPLEMENTED = FEATURE_RC_LAYER | BASE_RC_NOT_IMPLEMENTED
    FAPI_RC_BAD_REFERENCE = FEATURE_RC_LAYER | BASE_RC_BAD_REFERENCE
    FAPI_RC_BAD_SEQUENCE = FEATURE_RC_LAYER | BASE_RC_BAD_SEQUENCE
    FAPI_RC_IO_ERROR = FEATURE_RC_LAYER | BASE_RC_IO_ERROR
    FAPI_RC_BAD_VALUE = FEATURE_RC_LAYER | BASE_RC_BAD_VALUE
    FAPI_RC_NO_DECRYPT_PARAM = FEATURE_RC_LAYER | BASE_RC_NO_DECRYPT_PARAM
    FAPI_RC_NO_ENCRYPT_PARAM = FEATURE_RC_LAYER | BASE_RC_NO_ENCRYPT_PARAM
    FAPI_RC_MEMORY = FEATURE_RC_LAYER | BASE_RC_MEMORY
    FAPI_RC_BAD_CONTEXT = FEATURE_RC_LAYER | BASE_RC_BAD_CONTEXT
    FAPI_RC_NO_CONFIG = FEATURE_RC_LAYER | BASE_RC_NO_CONFIG
    FAPI_RC_BAD_PATH = FEATURE_RC_LAYER | BASE_RC_BAD_PATH
    FAPI_RC_NOT_DELETABLE = FEATURE_RC_LAYER | BASE_RC_NOT_DELETABLE
    FAPI_RC_PATH_ALREADY_EXISTS = FEATURE_RC_LAYER | BASE_RC_PATH_ALREADY_EXISTS
    FAPI_RC_KEY_NOT_FOUND = FEATURE_RC_LAYER | BASE_RC_KEY_NOT_FOUND
    FAPI_RC_SIGNATURE_VERIFICATION_FAILED = (
        FEATURE_RC_LAYER | BASE_RC_SIGNATURE_VERIFICATION_FAILED
    )
    FAPI_RC_HASH_MISMATCH = FEATURE_RC_LAYER | BASE_RC_HASH_MISMATCH
    FAPI_RC_KEY_NOT_DUPLICABLE = FEATURE_RC_LAYER | BASE_RC_KEY_NOT_DUPLICABLE
    FAPI_RC_PATH_NOT_FOUND = FEATURE_RC_LAYER | BASE_RC_PATH_NOT_FOUND
    FAPI_RC_NO_CERT = FEATURE_RC_LAYER | BASE_RC_NO_CERT
    FAPI_RC_NO_PCR = FEATURE_RC_LAYER | BASE_RC_NO_PCR
    FAPI_RC_PCR_NOT_RESETTABLE = FEATURE_RC_LAYER | BASE_RC_PCR_NOT_RESETTABLE
    FAPI_RC_BAD_TEMPLATE = FEATURE_RC_LAYER | BASE_RC_BAD_TEMPLATE
    FAPI_RC_AUTHORIZATION_FAILED = FEATURE_RC_LAYER | BASE_RC_AUTHORIZATION_FAILED
    FAPI_RC_AUTHORIZATION_UNKNOWN = FEATURE_RC_LAYER | BASE_RC_AUTHORIZATION_UNKNOWN
    FAPI_RC_NV_NOT_READABLE = FEATURE_RC_LAYER | BASE_RC_NV_NOT_READABLE
    FAPI_RC_NV_TOO_SMALL = FEATURE_RC_LAYER | BASE_RC_NV_TOO_SMALL
    FAPI_RC_NV_NOT_WRITEABLE = FEATURE_RC_LAYER | BASE_RC_NV_NOT_WRITEABLE
    FAPI_RC_POLICY_UNKNOWN = FEATURE_RC_LAYER | BASE_RC_POLICY_UNKNOWN
    FAPI_RC_NV_WRONG_TYPE = FEATURE_RC_LAYER | BASE_RC_NV_WRONG_TYPE
    FAPI_RC_NAME_ALREADY_EXISTS = FEATURE_RC_LAYER | BASE_RC_NAME_ALREADY_EXISTS
    FAPI_RC_NO_TPM = FEATURE_RC_LAYER | BASE_RC_NO_TPM
    FAPI_RC_TRY_AGAIN = FEATURE_RC_LAYER | BASE_RC_TRY_AGAIN
    FAPI_RC_BAD_KEY = FEATURE_RC_LAYER | BASE_RC_BAD_KEY
    FAPI_RC_NO_HANDLE = FEATURE_RC_LAYER | BASE_RC_NO_HANDLE
    FAPI_RC_NOT_PROVISIONED = FEATURE_RC_LAYER | BASE_RC_NOT_PROVISIONED
    FAPI_RC_ALREADY_PROVISIONED = FEATURE_RC_LAYER | BASE_RC_ALREADY_PROVISIONED

    POLICY_RC_GENERAL_FAILURE = POLICY_RC_LAYER | BASE_RC_GENERAL_FAILURE
    POLICY_RC_IO_ERROR = POLICY_RC_LAYER | BASE_RC_IO_ERROR
    POLICY_RC_AUTHORIZATION_UNKNOWN = POLICY_RC_LAYER | BASE_RC_AUTHORIZATION_UNKNOWN
    POLICY_RC_BAD_VALUE = POLICY_RC_LAYER | BASE_RC_BAD_VALUE
    POLICY_RC_MEMORY = POLICY_RC_LAYER | BASE_RC_MEMORY
    POLICY_RC_BAD_REFERENCE = POLICY_RC_LAYER | BASE_RC_BAD_REFERENCE
    POLICY_RC_BAD_TEMPLATE = POLICY_RC_LAYER | BASE_RC_BAD_TEMPLATE
    POLICY_RC_POLICY_NOT_CALCULATED = POLICY_RC_LAYER | BASE_RC_NOT_PROVISIONED
    POLICY_RC_BUFFER_TOO_SMALL = POLICY_RC_LAYER | BASE_RC_BAD_SIZE
    POLICY_RC_NULL_CALLBACK = POLICY_RC_LAYER | BASE_RC_CALLBACK_NULL


class TPM2_EO(TPM_FRIENDLY_INT):
    EQ = 0x0000
    NEQ = 0x0001
    SIGNED_GT = 0x0002
    UNSIGNED_GT = 0x0003
    SIGNED_LT = 0x0004
    UNSIGNED_LT = 0x0005
    SIGNED_GE = 0x0006
    UNSIGNED_GE = 0x0007
    SIGNED_LE = 0x0008
    UNSIGNED_LE = 0x0009
    BITSET = 0x000A
    BITCLEAR = 0x000B


class TPM2_ST(TPM_FRIENDLY_INT):
    RSP_COMMAND = 0x00C4
    NULL = 0x8000
    NO_SESSIONS = 0x8001
    SESSIONS = 0x8002
    ATTEST_NV = 0x8014
    ATTEST_COMMAND_AUDIT = 0x8015
    ATTEST_SESSION_AUDIT = 0x8016
    ATTEST_CERTIFY = 0x8017
    ATTEST_QUOTE = 0x8018
    ATTEST_TIME = 0x8019
    ATTEST_CREATION = 0x801A
    CREATION = 0x8021
    VERIFIED = 0x8022
    AUTH_SECRET = 0x8023
    HASHCHECK = 0x8024
    AUTH_SIGNED = 0x8025
    FU_MANIFEST = 0x8029


class TPM2_SU(TPM_FRIENDLY_INT):
    CLEAR = 0x0000
    STATE = 0x0001


class TPM2_SE(TPM_FRIENDLY_INT):
    HMAC = 0x00
    POLICY = 0x01
    TRIAL = 0x03


class TPM2_CAP(TPM_FRIENDLY_INT):
    FIRST = 0x00000000
    ALGS = 0x00000000
    HANDLES = 0x00000001
    COMMANDS = 0x00000002
    PP_COMMANDS = 0x00000003
    AUDIT_COMMANDS = 0x00000004
    PCRS = 0x00000005
    TPM_PROPERTIES = 0x00000006
    PCR_PROPERTIES = 0x00000007
    ECC_CURVES = 0x00000008
    AUTH_POLICIES = 0x00000009
    ACT = 0x0000000A
    LAST = 0x0000000A
    VENDOR_PROPERTY = 0x00000100


class TPMI_YES_NO(TPM_FRIENDLY_INT):
    YES = 1
    NO = 0


class TPM_AT(TPM_FRIENDLY_INT):
    ANY = 0x00000000
    ERROR = 0x00000001
    PV1 = 0x00000002
    VEND = 0x80000000


class TPM2_PT(TPM_FRIENDLY_INT):
    NONE = 0x00000000
    GROUP = 0x00000100
    FIXED = GROUP * 1
    VAR = GROUP * 2
    LOCKOUT_COUNTER = VAR + 14
    LEVEL = FIXED + 1
    REVISION = FIXED + 2
    DAY_OF_YEAR = FIXED + 3
    YEAR = FIXED + 4
    MANUFACTURER = FIXED + 5
    FAMILY_INDICATOR = FIXED + 0
    INPUT_BUFFER = FIXED + 13
    ACTIVE_SESSIONS_MAX = FIXED + 17
    CONTEXT_GAP_MAX = FIXED + 20
    MEMORY = FIXED + 24
    CLOCK_UPDATE = FIXED + 25
    ORDERLY_COUNT = FIXED + 29
    MAX_COMMAND_SIZE = FIXED + 30
    MAX_RESPONSE_SIZE = FIXED + 31
    MAX_DIGEST = FIXED + 32
    MAX_OBJECT_CONTEXT = FIXED + 33
    MAX_SESSION_CONTEXT = FIXED + 34
    SPLIT_MAX = FIXED + 40
    TOTAL_COMMANDS = FIXED + 41
    VENDOR_COMMANDS = FIXED + 43
    MODES = FIXED + 45
    PERMANENT = VAR + 0
    STARTUP_CLEAR = VAR + 1
    LIBRARY_COMMANDS = FIXED + 42
    ALGORITHM_SET = VAR + 12
    LOADED_CURVES = VAR + 13
    MAX_AUTH_FAIL = VAR + 15
    LOCKOUT_INTERVAL = VAR + 16
    LOCKOUT_RECOVERY = VAR + 17


class TPM2_PT_VENDOR(TPM_FRIENDLY_INT):
    STRING_1 = TPM2_PT.FIXED + 6
    STRING_2 = TPM2_PT.FIXED + 7
    STRING_3 = TPM2_PT.FIXED + 8
    STRING_4 = TPM2_PT.FIXED + 9
    TPM_TYPE = TPM2_PT.FIXED + 10


class TPM2_PT_FIRMWARE(TPM_FRIENDLY_INT):
    VERSION_1 = TPM2_PT.FIXED + 11
    VERSION_2 = TPM2_PT.FIXED + 12


class TPM2_PT_HR(TPM_FRIENDLY_INT):
    LOADED_MIN = TPM2_PT.FIXED + 16
    NV_INDEX = TPM2_PT.VAR + 2
    LOADED = TPM2_PT.VAR + 3
    LOADED_AVAIL = TPM2_PT.VAR + 4
    ACTIVE = TPM2_PT.VAR + 5
    ACTIVE_AVAIL = TPM2_PT.VAR + 6
    TRANSIENT_AVAIL = TPM2_PT.VAR + 7
    PERSISTENT = TPM2_PT.VAR + 8
    PERSISTENT_AVAIL = TPM2_PT.VAR + 9
    TRANSIENT_MIN = TPM2_PT.FIXED + 14
    PERSISTENT_MIN = TPM2_PT.FIXED + 15


class TPM2_PT_NV(TPM_FRIENDLY_INT):
    COUNTERS_MAX = TPM2_PT.FIXED + 22
    INDEX_MAX = TPM2_PT.FIXED + 23
    BUFFER_MAX = TPM2_PT.FIXED + 44
    COUNTERS = TPM2_PT.VAR + 10
    COUNTERS_AVAIL = TPM2_PT.VAR + 11
    WRITE_RECOVERY = TPM2_PT.VAR + 18


class TPM2_PT_CONTEXT(TPM_FRIENDLY_INT):
    HASH = TPM2_PT.FIXED + 26
    SYM = TPM2_PT.FIXED + 27
    SYM_SIZE = TPM2_PT.FIXED + 28


class TPM2_PT_PS(TPM_FRIENDLY_INT):
    FAMILY_INDICATOR = TPM2_PT.FIXED + 35
    LEVEL = TPM2_PT.FIXED + 36
    REVISION = TPM2_PT.FIXED + 37
    DAY_OF_YEAR = TPM2_PT.FIXED + 38
    YEAR = TPM2_PT.FIXED + 39


class TPM2_PT_AUDIT(TPM_FRIENDLY_INT):
    COUNTER_0 = TPM2_PT.VAR + 19
    COUNTER_1 = TPM2_PT.VAR + 20


class TPM2_PT_PCR(TPM_FRIENDLY_INT):
    FIRST = 0x00000000
    SAVE = 0x00000000
    EXTEND_L0 = 0x00000001
    RESET_L0 = 0x00000002
    EXTEND_L1 = 0x00000003
    RESET_L1 = 0x00000004
    EXTEND_L2 = 0x00000005
    RESET_L2 = 0x00000006
    EXTEND_L3 = 0x00000007
    RESET_L3 = 0x00000008
    EXTEND_L4 = 0x00000009
    RESET_L4 = 0x0000000A
    NO_INCREMENT = 0x00000011
    DRTM_RESET = 0x00000012
    POLICY = 0x00000013
    AUTH = 0x00000014
    LAST = 0x00000014
    COUNT = TPM2_PT.FIXED + 18
    SELECT_MIN = TPM2_PT.FIXED + 19


class TPM2_PS(TPM_FRIENDLY_INT):
    MAIN = 0x00000000
    PC = 0x00000001
    PDA = 0x00000002
    CELL_PHONE = 0x00000003
    SERVER = 0x00000004
    PERIPHERAL = 0x00000005
    TSS = 0x00000006
    STORAGE = 0x00000007
    AUTHENTICATION = 0x00000008
    EMBEDDED = 0x00000009
    HARDCOPY = 0x0000000A
    INFRASTRUCTURE = 0x0000000B
    VIRTUALIZATION = 0x0000000C
    TNC = 0x0000000D
    MULTI_TENANT = 0x0000000E
    TC = 0x0000000F


class TPM2_HT(TPM_FRIENDLY_INT):
    PCR = 0x00
    NV_INDEX = 0x01
    HMAC_SESSION = 0x02
    LOADED_SESSION = 0x02
    POLICY_SESSION = 0x03
    SAVED_SESSION = 0x03
    PERMANENT = 0x40
    TRANSIENT = 0x80
    PERSISTENT = 0x81


class TPMA_SESSION(TPMA_FRIENDLY_INTLIST):
    CONTINUESESSION = 0x00000001
    AUDITEXCLUSIVE = 0x00000002
    AUDITRESET = 0x00000004
    DECRYPT = 0x00000020
    ENCRYPT = 0x00000040
    AUDIT = 0x00000080


class TPMA_LOCALITY(TPMA_FRIENDLY_INTLIST):
    ZERO = 0x00000001
    ONE = 0x00000002
    TWO = 0x00000004
    THREE = 0x00000008
    FOUR = 0x00000010
    EXTENDED_MASK = 0x000000E0
    EXTENDED_SHIFT = 5

    @classmethod
    def create_extended(cls, value):
        x = (1 << cls.EXTENDED_SHIFT) + value
        if x > 255:
            raise ValueError("Extended Localities must be less than 256")
        return x

    @classmethod
    def parse(cls, value: str) -> "TPMA_LOCALITY":
        """Converts a string of | separated localities or an extended locality into a TPMA_LOCALITY instance

        Args:
            value (str): The string "bitwise" expression of the localities or the extended locality.

        Returns:
            The locality or set of localities as a TPMA_LOCALITY instance.

        Raises:
            TypeError: If the value is not a str.
            ValueError: If a field portion of the str does not match a constant.

        Examples:
            TPMA_LOCALITY.parse("zero|one") -> 0x03
            TPMA_LOCALITY.parse("0xf0") -> 0xf0
        """
        try:
            return cls(value, base=0)
        except ValueError:
            pass
        return super().parse(value)

    def __str__(self) -> str:
        """Given a set of localities or an extended locality, return the string representation

        Returns:
            (str): a bitwise string value of the localities or the exteded locality.

        Example:
            str(TPMA_LOCALITY.THREE|TPMA_LOCALITY.FOUR) -> 'three|four'
            str(TPMA_LOCALITY(0xf0)) -> '0xf0'
        """
        if self > 31:
            return f"{self:#x}"
        return super().__str__()


class TPM2_NT(TPM_FRIENDLY_INT):
    ORDINARY = 0x0
    COUNTER = 0x1
    BITS = 0x2
    EXTEND = 0x4
    PIN_FAIL = 0x8
    PIN_PASS = 0x9


class TPM2_HR(TPM_FRIENDLY_INT):
    HANDLE_MASK = 0x00FFFFFF
    RANGE_MASK = 0xFF000000
    SHIFT = 24
    PCR = TPM2_HT.PCR << SHIFT
    HMAC_SESSION = TPM2_HT.HMAC_SESSION << SHIFT
    POLICY_SESSION = TPM2_HT.POLICY_SESSION << SHIFT
    TRANSIENT = TPM2_HT.TRANSIENT << SHIFT
    PERSISTENT = TPM2_HT.PERSISTENT << SHIFT
    NV_INDEX = TPM2_HT.NV_INDEX << SHIFT
    PERMANENT = TPM2_HT.PERMANENT << SHIFT


class TPM2_HC(TPM_FRIENDLY_INT):
    HR_HANDLE_MASK = 0x00FFFFFF
    HR_RANGE_MASK = 0xFF000000
    HR_SHIFT = 24
    HR_PCR = TPM2_HT.PCR << HR_SHIFT
    HR_HMAC_SESSION = TPM2_HT.HMAC_SESSION << HR_SHIFT
    HR_POLICY_SESSION = TPM2_HT.POLICY_SESSION << HR_SHIFT
    HR_TRANSIENT = TPM2_HT.TRANSIENT << HR_SHIFT
    HR_PERSISTENT = TPM2_HT.PERSISTENT << HR_SHIFT
    HR_NV_INDEX = TPM2_HT.NV_INDEX << HR_SHIFT
    HR_PERMANENT = TPM2_HT.PERMANENT << HR_SHIFT
    PCR_FIRST = HR_PCR + 0
    PCR_LAST = HR_PCR + TPM2_MAX.PCRS
    HMAC_SESSION_FIRST = HR_HMAC_SESSION + 0
    HMAC_SESSION_LAST = HMAC_SESSION_FIRST + 0x00FFFFFE
    LOADED_SESSION_FIRST = HMAC_SESSION_FIRST
    LOADED_SESSION_LAST = HMAC_SESSION_LAST
    POLICY_SESSION_FIRST = HR_POLICY_SESSION + 0
    POLICY_SESSION_LAST = POLICY_SESSION_FIRST + 0x00FFFFFE
    TRANSIENT_FIRST = HR_TRANSIENT + 0
    ACTIVE_SESSION_FIRST = POLICY_SESSION_FIRST
    ACTIVE_SESSION_LAST = POLICY_SESSION_LAST
    TRANSIENT_LAST = TRANSIENT_FIRST + 0x00FFFFFE
    PERSISTENT_FIRST = HR_PERSISTENT + 0
    PERSISTENT_LAST = PERSISTENT_FIRST + 0x00FFFFFF
    PLATFORM_PERSISTENT = PERSISTENT_FIRST + 0x00800000
    NV_INDEX_FIRST = HR_NV_INDEX + 0
    NV_INDEX_LAST = HR_NV_INDEX + 0x00FFFFFF
    PERMANENT_FIRST = TPM2_RH.FIRST
    PERMANENT_LAST = TPM2_RH.LAST
    HR_NV_AC = (TPM2_HT.NV_INDEX << HR_SHIFT) + 0xD00000
    NV_AC_FIRST = HR_NV_AC + 0
    NV_AC_LAST = HR_NV_AC + 0x0000FFFF


class TPM2_CLOCK(TPM_FRIENDLY_INT):
    COARSE_SLOWER = -3
    MEDIUM_SLOWER = -2
    FINE_SLOWER = -1
    NO_CHANGE = 0
    FINE_FASTER = 1
    MEDIUM_FASTER = 2
    COARSE_FASTER = 3


class TPM2_CLOCK_ADJUST(TPM2_CLOCK):
    pass


class TPMA_NV(TPMA_FRIENDLY_INTLIST):

    _FIXUP_MAP = {"NODA": "NO_DA"}

    PPWRITE = 0x00000001
    OWNERWRITE = 0x00000002
    AUTHWRITE = 0x00000004
    POLICYWRITE = 0x00000008
    TPM2_NT_MASK = 0x000000F0
    TPM2_NT_SHIFT = 4
    POLICY_DELETE = 0x00000400
    WRITELOCKED = 0x00000800
    WRITEALL = 0x00001000
    WRITEDEFINE = 0x00002000
    WRITE_STCLEAR = 0x00004000
    GLOBALLOCK = 0x00008000
    PPREAD = 0x00010000
    OWNERREAD = 0x00020000
    AUTHREAD = 0x00040000
    POLICYREAD = 0x00080000
    NO_DA = 0x02000000
    ORDERLY = 0x04000000
    CLEAR_STCLEAR = 0x08000000
    READLOCKED = 0x10000000
    WRITTEN = 0x20000000
    PLATFORMCREATE = 0x40000000
    READ_STCLEAR = 0x80000000

    _MASKS = ((TPM2_NT_MASK, TPM2_NT_SHIFT, "nt"),)

    @property
    def nt(self) -> TPM2_NT:
        """TPM2_NT: The type of the NV area"""
        return TPM2_NT((self & self.TPM2_NT_MASK) >> self.TPM2_NT_SHIFT)


class TPMA_CC(TPMA_FRIENDLY_INTLIST):
    COMMANDINDEX_MASK = 0x0000FFFF
    COMMANDINDEX_SHIFT = 0
    RESERVED1_MASK = 0x003F0000
    NV = 0x00400000
    EXTENSIVE = 0x00800000
    FLUSHED = 0x01000000
    CHANDLES_MASK = 0x0E000000
    CHANDLES_SHIFT = 25
    RHANDLE = 0x10000000
    V = 0x20000000
    RES_MASK = 0xC0000000
    RES_SHIFT = 30

    _MASKS = (
        (COMMANDINDEX_MASK, COMMANDINDEX_SHIFT, "commandindex"),
        (CHANDLES_MASK, CHANDLES_SHIFT, "chandles"),
    )

    @property
    def commandindex(self) -> int:
        """int: The command index"""
        return self & self.COMMANDINDEX_MASK

    @property
    def chandles(self) -> int:
        """int: The number of handles in the handle area"""
        return (self & self.CHANDLES_MASK) >> self.CHANDLES_SHIFT


class TPMA_OBJECT(TPMA_FRIENDLY_INTLIST):
    FIXEDTPM = 0x00000002
    STCLEAR = 0x00000004
    FIXEDPARENT = 0x00000010
    SENSITIVEDATAORIGIN = 0x00000020
    USERWITHAUTH = 0x00000040
    ADMINWITHPOLICY = 0x00000080
    FIRMWARELIMITED = 0x00000100
    SVNLIMITED = 0x00000200
    NODA = 0x00000400
    ENCRYPTEDDUPLICATION = 0x00000800
    RESTRICTED = 0x00010000
    DECRYPT = 0x00020000
    SIGN_ENCRYPT = 0x00040000
    X509SIGN = 0x00080000

    DEFAULT_TPM2_TOOLS_CREATE_ATTRS = (
        DECRYPT
        | SIGN_ENCRYPT
        | FIXEDTPM
        | FIXEDPARENT
        | SENSITIVEDATAORIGIN
        | USERWITHAUTH
    )

    DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS = (
        RESTRICTED
        | DECRYPT
        | FIXEDTPM
        | FIXEDPARENT
        | SENSITIVEDATAORIGIN
        | USERWITHAUTH
    )

    _FIXUP_MAP = {
        "SIGN": "SIGN_ENCRYPT",
        "ENCRYPT": "SIGN_ENCRYPT",
    }


class TPMA_ALGORITHM(TPM_FRIENDLY_INT):
    ASYMMETRIC = 0x00000001
    SYMMETRIC = 0x00000002
    HASH = 0x00000004
    OBJECT = 0x00000008
    RESERVED1_MASK = 0x000000F0
    SIGNING = 0x00000100
    ENCRYPTING = 0x00000200
    METHOD = 0x00000400


class TPMA_PERMANENT(TPMA_FRIENDLY_INTLIST):
    OWNERAUTHSET = 0x00000001
    ENDORSEMENTAUTHSET = 0x00000002
    LOCKOUTAUTHSET = 0x00000004
    RESERVED1_MASK = 0x000000F8
    DISABLECLEAR = 0x00000100
    INLOCKOUT = 0x00000200
    TPMGENERATEDEPS = 0x00000400
    RESERVED2_MASK = 0xFFFFF800


class TPMA_STARTUP(TPMA_FRIENDLY_INTLIST):
    CLEAR_PHENABLE = 0x00000001
    CLEAR_SHENABLE = 0x00000002
    CLEAR_EHENABLE = 0x00000004
    CLEAR_PHENABLENV = 0x00000008
    CLEAR_RESERVED1_MASK = 0x7FFFFFF0
    CLEAR_ORDERLY = 0x80000000


class TPMA_MEMORY(TPM_FRIENDLY_INT):
    SHAREDRAM = 0x00000001
    SHAREDNV = 0x00000002
    OBJECTCOPIEDTORAM = 0x00000004


class TPMA_MODES(TPMA_FRIENDLY_INTLIST):
    FIPS_140_2 = 0x00000001
    RESERVED1_MASK = 0xFFFFFFFE


class TPMA_X509_KEY_USAGE(TPMA_FRIENDLY_INTLIST):
    DECIPHER_ONLY = 0x00800000
    ENCIPHER_ONLY = 0x01000000
    CRLSIGN = 0x02000000
    KEYCERTSIGN = 0x04000000
    KEYAGREEMENT = 0x08000000
    DATAENCIPHERMENT = 0x10000000
    KEYENCIPHERMENT = 0x20000000
    NONREPUDIATION = 0x40000000
    DIGITALSIGNATURE = 0x80000000


class TPMA_ACT(TPMA_FRIENDLY_INTLIST):
    SIGNALED = 0x00000000
    PRESERVESIGNALED = 0x00000001


#
# We specifically keep these constants around even when FAPI is missing so they may be used
# without conditional worry and we DONT use lib prefix here because the constants are only
# present if FAPI is installed. So just use the values directly.
#
class FAPI_ESYSBLOB(TPM_FRIENDLY_INT):
    CONTEXTLOAD = 1
    DESERIALIZE = 2


class TSS2_POLICY_PCR_SELECTOR(TPM_FRIENDLY_INT):
    PCR_SELECT = 0
    PCR_SELECTION = 1


# Max value for INT32
TPM2_MAX_EXPIRATION = -0x7FFFFFFF
