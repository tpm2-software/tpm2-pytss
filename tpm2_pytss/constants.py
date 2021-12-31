# SPDX-License-Identifier: BSD-2
""" This module contains all the constant values from the following TCG specifications:

- https://trustedcomputinggroup.org/resource/tpm-library-specification/. See Part 2 "Structures".
- https://trustedcomputinggroup.org/resource/tss-overview-common-structures-specification

Along with helpers to go from string values to constants and constant values to string values.
"""
from ._libtpm2_pytss import lib, ffi
from tpm2_pytss.internal.utils import _CLASS_INT_ATTRS_from_string
import pkgconfig


class TPM_FRIENDLY_INT(int):
    _FIXUP_MAP = {}

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
    def iterator(cls) -> filter:
        """ Returns the constants in the class.

        Returns:
            (int): The int values of the constants in the class.

        Example:
            list(ESYS_TR.iterator()) -> [4095, 255, 0, 1, 2, 3, ... ]
        """
        return filter(lambda x: isinstance(x, int), vars(cls).values())

    @classmethod
    def contains(cls, value: int) -> bool:
        """ Indicates if a class contains a numeric constant.

        Args:
            value (int): The raw numerical number to test for.

        Returns:
            (bool): True if the class contains the constant, False otherwise.

        Example:
            ESYS_TR.contains(7) -> True
        """
        return value in cls.iterator()

    @classmethod
    def to_string(cls, value: int) -> str:
        """ Converts an integer value into it's friendly string name for that class.

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

    @staticmethod
    def _fix_const_type(cls):
        for k, v in vars(cls).items():
            if not isinstance(v, int) or k.startswith("_"):
                continue
            fv = cls(v)
            setattr(cls, k, fv)
        return cls


class TPMA_FRIENDLY_INTLIST(TPM_FRIENDLY_INT):
    _MASKS = tuple()

    @classmethod
    def parse(cls, value: str) -> int:
        """ Converts a string of | separated constant values into it's integer value.

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


@TPM_FRIENDLY_INT._fix_const_type
class ESYS_TR(TPM_FRIENDLY_INT):
    """ESYS_TR is an ESAPI identifier representing a TPM resource

    To get the ESYS_TR identifier for a persistent handle, such as a NV area
    or a persistent key use :func:`tpm2_pytss.ESAPI.tr_from_tpmpublic`
    """

    NONE = lib.ESYS_TR_NONE
    PASSWORD = lib.ESYS_TR_PASSWORD
    PCR0 = lib.ESYS_TR_PCR0
    PCR1 = lib.ESYS_TR_PCR1
    PCR2 = lib.ESYS_TR_PCR2
    PCR3 = lib.ESYS_TR_PCR3
    PCR4 = lib.ESYS_TR_PCR4
    PCR5 = lib.ESYS_TR_PCR5
    PCR6 = lib.ESYS_TR_PCR6
    PCR7 = lib.ESYS_TR_PCR7
    PCR8 = lib.ESYS_TR_PCR8
    PCR9 = lib.ESYS_TR_PCR9
    PCR10 = lib.ESYS_TR_PCR10
    PCR11 = lib.ESYS_TR_PCR11
    PCR12 = lib.ESYS_TR_PCR12
    PCR13 = lib.ESYS_TR_PCR13
    PCR14 = lib.ESYS_TR_PCR14
    PCR15 = lib.ESYS_TR_PCR15
    PCR16 = lib.ESYS_TR_PCR16
    PCR17 = lib.ESYS_TR_PCR17
    PCR18 = lib.ESYS_TR_PCR18
    PCR19 = lib.ESYS_TR_PCR19
    PCR20 = lib.ESYS_TR_PCR20
    PCR21 = lib.ESYS_TR_PCR21
    PCR22 = lib.ESYS_TR_PCR22
    PCR23 = lib.ESYS_TR_PCR23
    PCR24 = lib.ESYS_TR_PCR24
    PCR25 = lib.ESYS_TR_PCR25
    PCR26 = lib.ESYS_TR_PCR26
    PCR27 = lib.ESYS_TR_PCR27
    PCR28 = lib.ESYS_TR_PCR28
    PCR29 = lib.ESYS_TR_PCR29
    PCR30 = lib.ESYS_TR_PCR30
    PCR31 = lib.ESYS_TR_PCR31
    OWNER = lib.ESYS_TR_RH_OWNER
    NULL = lib.ESYS_TR_RH_NULL
    LOCKOUT = lib.ESYS_TR_RH_LOCKOUT
    ENDORSEMENT = lib.ESYS_TR_RH_ENDORSEMENT
    PLATFORM = lib.ESYS_TR_RH_PLATFORM
    PLATFORM_NV = lib.ESYS_TR_RH_PLATFORM_NV
    RH_OWNER = lib.ESYS_TR_RH_OWNER
    RH_NULL = lib.ESYS_TR_RH_NULL
    RH_LOCKOUT = lib.ESYS_TR_RH_LOCKOUT
    RH_ENDORSEMENT = lib.ESYS_TR_RH_ENDORSEMENT
    RH_PLATFORM = lib.ESYS_TR_RH_PLATFORM
    RH_PLATFORM_NV = lib.ESYS_TR_RH_PLATFORM_NV

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


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_RH(TPM_FRIENDLY_INT):
    SRK = lib.TPM2_RH_SRK
    OWNER = lib.TPM2_RH_OWNER
    REVOKE = lib.TPM2_RH_REVOKE
    TRANSPORT = lib.TPM2_RH_TRANSPORT
    OPERATOR = lib.TPM2_RH_OPERATOR
    ADMIN = lib.TPM2_RH_ADMIN
    EK = lib.TPM2_RH_EK
    NULL = lib.TPM2_RH_NULL
    UNASSIGNED = lib.TPM2_RH_UNASSIGNED
    try:
        PW = lib.TPM2_RS_PW
    except AttributeError:
        PW = lib.TPM2_RH_PW
    LOCKOUT = lib.TPM2_RH_LOCKOUT
    ENDORSEMENT = lib.TPM2_RH_ENDORSEMENT
    PLATFORM = lib.TPM2_RH_PLATFORM
    PLATFORM_NV = lib.TPM2_RH_PLATFORM_NV


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_ALG(TPM_FRIENDLY_INT):
    ERROR = lib.TPM2_ALG_ERROR
    RSA = lib.TPM2_ALG_RSA
    SHA = lib.TPM2_ALG_SHA
    SHA1 = lib.TPM2_ALG_SHA1
    HMAC = lib.TPM2_ALG_HMAC
    AES = lib.TPM2_ALG_AES
    MGF1 = lib.TPM2_ALG_MGF1
    KEYEDHASH = lib.TPM2_ALG_KEYEDHASH
    XOR = lib.TPM2_ALG_XOR
    SHA256 = lib.TPM2_ALG_SHA256
    SHA384 = lib.TPM2_ALG_SHA384
    SHA512 = lib.TPM2_ALG_SHA512
    NULL = lib.TPM2_ALG_NULL
    SM3_256 = lib.TPM2_ALG_SM3_256
    SM4 = lib.TPM2_ALG_SM4
    RSASSA = lib.TPM2_ALG_RSASSA
    RSAES = lib.TPM2_ALG_RSAES
    RSAPSS = lib.TPM2_ALG_RSAPSS
    OAEP = lib.TPM2_ALG_OAEP
    ECDSA = lib.TPM2_ALG_ECDSA
    ECDH = lib.TPM2_ALG_ECDH
    ECDAA = lib.TPM2_ALG_ECDAA
    SM2 = lib.TPM2_ALG_SM2
    ECSCHNORR = lib.TPM2_ALG_ECSCHNORR
    ECMQV = lib.TPM2_ALG_ECMQV
    KDF1_SP800_56A = lib.TPM2_ALG_KDF1_SP800_56A
    KDF2 = lib.TPM2_ALG_KDF2
    KDF1_SP800_108 = lib.TPM2_ALG_KDF1_SP800_108
    ECC = lib.TPM2_ALG_ECC
    SYMCIPHER = lib.TPM2_ALG_SYMCIPHER
    CAMELLIA = lib.TPM2_ALG_CAMELLIA
    CTR = lib.TPM2_ALG_CTR
    SHA3_256 = lib.TPM2_ALG_SHA3_256
    SHA3_384 = lib.TPM2_ALG_SHA3_384
    SHA3_512 = lib.TPM2_ALG_SHA3_512
    OFB = lib.TPM2_ALG_OFB
    CBC = lib.TPM2_ALG_CBC
    CFB = lib.TPM2_ALG_CFB
    ECB = lib.TPM2_ALG_ECB
    FIRST = lib.TPM2_ALG_FIRST
    LAST = lib.TPM2_ALG_LAST


TPM2_ALG_ID = TPM2_ALG


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_ECC(TPM_FRIENDLY_INT):
    NONE = lib.TPM2_ECC_NONE
    NIST_P192 = lib.TPM2_ECC_NIST_P192
    NIST_P224 = lib.TPM2_ECC_NIST_P224
    NIST_P256 = lib.TPM2_ECC_NIST_P256
    NIST_P384 = lib.TPM2_ECC_NIST_P384
    NIST_P521 = lib.TPM2_ECC_NIST_P521
    BN_P256 = lib.TPM2_ECC_BN_P256
    BN_P638 = lib.TPM2_ECC_BN_P638
    SM2_P256 = lib.TPM2_ECC_SM2_P256

    _FIXUP_MAP = {
        "192": "NIST_P192",
        "224": "NIST_P224",
        "256": "NIST_P256",
        "384": "NIST_P384",
        "521": "NIST_P521",
    }


TPM2_ECC_CURVE = TPM2_ECC


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_CC(TPM_FRIENDLY_INT):
    NV_UndefineSpaceSpecial = lib.TPM2_CC_NV_UndefineSpaceSpecial
    FIRST = lib.TPM2_CC_FIRST
    EvictControl = lib.TPM2_CC_EvictControl
    HierarchyControl = lib.TPM2_CC_HierarchyControl
    NV_UndefineSpace = lib.TPM2_CC_NV_UndefineSpace
    ChangeEPS = lib.TPM2_CC_ChangeEPS
    ChangePPS = lib.TPM2_CC_ChangePPS
    Clear = lib.TPM2_CC_Clear
    ClearControl = lib.TPM2_CC_ClearControl
    ClockSet = lib.TPM2_CC_ClockSet
    HierarchyChangeAuth = lib.TPM2_CC_HierarchyChangeAuth
    NV_DefineSpace = lib.TPM2_CC_NV_DefineSpace
    PCR_Allocate = lib.TPM2_CC_PCR_Allocate
    PCR_SetAuthPolicy = lib.TPM2_CC_PCR_SetAuthPolicy
    PP_Commands = lib.TPM2_CC_PP_Commands
    SetPrimaryPolicy = lib.TPM2_CC_SetPrimaryPolicy
    FieldUpgradeStart = lib.TPM2_CC_FieldUpgradeStart
    ClockRateAdjust = lib.TPM2_CC_ClockRateAdjust
    CreatePrimary = lib.TPM2_CC_CreatePrimary
    NV_GlobalWriteLock = lib.TPM2_CC_NV_GlobalWriteLock
    GetCommandAuditDigest = lib.TPM2_CC_GetCommandAuditDigest
    NV_Increment = lib.TPM2_CC_NV_Increment
    NV_SetBits = lib.TPM2_CC_NV_SetBits
    NV_Extend = lib.TPM2_CC_NV_Extend
    NV_Write = lib.TPM2_CC_NV_Write
    NV_WriteLock = lib.TPM2_CC_NV_WriteLock
    DictionaryAttackLockReset = lib.TPM2_CC_DictionaryAttackLockReset
    DictionaryAttackParameters = lib.TPM2_CC_DictionaryAttackParameters
    NV_ChangeAuth = lib.TPM2_CC_NV_ChangeAuth
    PCR_Event = lib.TPM2_CC_PCR_Event
    PCR_Reset = lib.TPM2_CC_PCR_Reset
    SequenceComplete = lib.TPM2_CC_SequenceComplete
    SetAlgorithmSet = lib.TPM2_CC_SetAlgorithmSet
    SetCommandCodeAuditStatus = lib.TPM2_CC_SetCommandCodeAuditStatus
    FieldUpgradeData = lib.TPM2_CC_FieldUpgradeData
    IncrementalSelfTest = lib.TPM2_CC_IncrementalSelfTest
    SelfTest = lib.TPM2_CC_SelfTest
    Startup = lib.TPM2_CC_Startup
    Shutdown = lib.TPM2_CC_Shutdown
    StirRandom = lib.TPM2_CC_StirRandom
    ActivateCredential = lib.TPM2_CC_ActivateCredential
    Certify = lib.TPM2_CC_Certify
    PolicyNV = lib.TPM2_CC_PolicyNV
    CertifyCreation = lib.TPM2_CC_CertifyCreation
    Duplicate = lib.TPM2_CC_Duplicate
    GetTime = lib.TPM2_CC_GetTime
    GetSessionAuditDigest = lib.TPM2_CC_GetSessionAuditDigest
    NV_Read = lib.TPM2_CC_NV_Read
    NV_ReadLock = lib.TPM2_CC_NV_ReadLock
    ObjectChangeAuth = lib.TPM2_CC_ObjectChangeAuth
    PolicySecret = lib.TPM2_CC_PolicySecret
    Rewrap = lib.TPM2_CC_Rewrap
    Create = lib.TPM2_CC_Create
    ECDH_ZGen = lib.TPM2_CC_ECDH_ZGen
    HMAC = lib.TPM2_CC_HMAC
    Import = lib.TPM2_CC_Import
    Load = lib.TPM2_CC_Load
    Quote = lib.TPM2_CC_Quote
    RSA_Decrypt = lib.TPM2_CC_RSA_Decrypt
    HMAC_Start = lib.TPM2_CC_HMAC_Start
    SequenceUpdate = lib.TPM2_CC_SequenceUpdate
    Sign = lib.TPM2_CC_Sign
    Unseal = lib.TPM2_CC_Unseal
    PolicySigned = lib.TPM2_CC_PolicySigned
    ContextLoad = lib.TPM2_CC_ContextLoad
    ContextSave = lib.TPM2_CC_ContextSave
    ECDH_KeyGen = lib.TPM2_CC_ECDH_KeyGen
    EncryptDecrypt = lib.TPM2_CC_EncryptDecrypt
    FlushContext = lib.TPM2_CC_FlushContext
    LoadExternal = lib.TPM2_CC_LoadExternal
    MakeCredential = lib.TPM2_CC_MakeCredential
    NV_ReadPublic = lib.TPM2_CC_NV_ReadPublic
    PolicyAuthorize = lib.TPM2_CC_PolicyAuthorize
    PolicyAuthValue = lib.TPM2_CC_PolicyAuthValue
    PolicyCommandCode = lib.TPM2_CC_PolicyCommandCode
    PolicyCounterTimer = lib.TPM2_CC_PolicyCounterTimer
    PolicyCpHash = lib.TPM2_CC_PolicyCpHash
    PolicyLocality = lib.TPM2_CC_PolicyLocality
    PolicyNameHash = lib.TPM2_CC_PolicyNameHash
    PolicyOR = lib.TPM2_CC_PolicyOR
    PolicyTicket = lib.TPM2_CC_PolicyTicket
    ReadPublic = lib.TPM2_CC_ReadPublic
    RSA_Encrypt = lib.TPM2_CC_RSA_Encrypt
    StartAuthSession = lib.TPM2_CC_StartAuthSession
    VerifySignature = lib.TPM2_CC_VerifySignature
    ECC_Parameters = lib.TPM2_CC_ECC_Parameters
    FirmwareRead = lib.TPM2_CC_FirmwareRead
    GetCapability = lib.TPM2_CC_GetCapability
    GetRandom = lib.TPM2_CC_GetRandom
    GetTestResult = lib.TPM2_CC_GetTestResult
    Hash = lib.TPM2_CC_Hash
    PCR_Read = lib.TPM2_CC_PCR_Read
    PolicyPCR = lib.TPM2_CC_PolicyPCR
    PolicyRestart = lib.TPM2_CC_PolicyRestart
    ReadClock = lib.TPM2_CC_ReadClock
    PCR_Extend = lib.TPM2_CC_PCR_Extend
    PCR_SetAuthValue = lib.TPM2_CC_PCR_SetAuthValue
    NV_Certify = lib.TPM2_CC_NV_Certify
    EventSequenceComplete = lib.TPM2_CC_EventSequenceComplete
    HashSequenceStart = lib.TPM2_CC_HashSequenceStart
    PolicyPhysicalPresence = lib.TPM2_CC_PolicyPhysicalPresence
    PolicyDuplicationSelect = lib.TPM2_CC_PolicyDuplicationSelect
    PolicyGetDigest = lib.TPM2_CC_PolicyGetDigest
    TestParms = lib.TPM2_CC_TestParms
    Commit = lib.TPM2_CC_Commit
    PolicyPassword = lib.TPM2_CC_PolicyPassword
    ZGen_2Phase = lib.TPM2_CC_ZGen_2Phase
    EC_Ephemeral = lib.TPM2_CC_EC_Ephemeral
    PolicyNvWritten = lib.TPM2_CC_PolicyNvWritten
    PolicyTemplate = lib.TPM2_CC_PolicyTemplate
    CreateLoaded = lib.TPM2_CC_CreateLoaded
    PolicyAuthorizeNV = lib.TPM2_CC_PolicyAuthorizeNV
    EncryptDecrypt2 = lib.TPM2_CC_EncryptDecrypt2
    AC_GetCapability = lib.TPM2_CC_AC_GetCapability
    AC_Send = lib.TPM2_CC_AC_Send
    Policy_AC_SendSelect = lib.TPM2_CC_Policy_AC_SendSelect
    LAST = lib.TPM2_CC_LAST
    Vendor_TCG_Test = lib.TPM2_CC_Vendor_TCG_Test


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_SPEC(TPM_FRIENDLY_INT):
    FAMILY = lib.TPM2_SPEC_FAMILY
    LEVEL = lib.TPM2_SPEC_LEVEL
    VERSION = lib.TPM2_SPEC_VERSION
    YEAR = lib.TPM2_SPEC_YEAR
    DAY_OF_YEAR = lib.TPM2_SPEC_DAY_OF_YEAR


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_GENERATED_VALUE(TPM_FRIENDLY_INT):
    VALUE = lib.TPM2_GENERATED_VALUE


class TPM_BASE_RC(TPM_FRIENDLY_INT):
    def decode(self):
        return ffi.string(lib.Tss2_RC_Decode(self)).decode()


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_RC(TPM_BASE_RC):
    SUCCESS = lib.TPM2_RC_SUCCESS
    BAD_TAG = lib.TPM2_RC_BAD_TAG
    VER1 = lib.TPM2_RC_VER1
    INITIALIZE = lib.TPM2_RC_INITIALIZE
    FAILURE = lib.TPM2_RC_FAILURE
    SEQUENCE = lib.TPM2_RC_SEQUENCE
    PRIVATE = lib.TPM2_RC_PRIVATE
    HMAC = lib.TPM2_RC_HMAC
    DISABLED = lib.TPM2_RC_DISABLED
    EXCLUSIVE = lib.TPM2_RC_EXCLUSIVE
    AUTH_TYPE = lib.TPM2_RC_AUTH_TYPE
    AUTH_MISSING = lib.TPM2_RC_AUTH_MISSING
    POLICY = lib.TPM2_RC_POLICY
    PCR = lib.TPM2_RC_PCR
    PCR_CHANGED = lib.TPM2_RC_PCR_CHANGED
    UPGRADE = lib.TPM2_RC_UPGRADE
    TOO_MANY_CONTEXTS = lib.TPM2_RC_TOO_MANY_CONTEXTS
    AUTH_UNAVAILABLE = lib.TPM2_RC_AUTH_UNAVAILABLE
    REBOOT = lib.TPM2_RC_REBOOT
    UNBALANCED = lib.TPM2_RC_UNBALANCED
    COMMAND_SIZE = lib.TPM2_RC_COMMAND_SIZE
    COMMAND_CODE = lib.TPM2_RC_COMMAND_CODE
    AUTHSIZE = lib.TPM2_RC_AUTHSIZE
    AUTH_CONTEXT = lib.TPM2_RC_AUTH_CONTEXT
    NV_RANGE = lib.TPM2_RC_NV_RANGE
    NV_SIZE = lib.TPM2_RC_NV_SIZE
    NV_LOCKED = lib.TPM2_RC_NV_LOCKED
    NV_AUTHORIZATION = lib.TPM2_RC_NV_AUTHORIZATION
    NV_UNINITIALIZED = lib.TPM2_RC_NV_UNINITIALIZED
    NV_SPACE = lib.TPM2_RC_NV_SPACE
    NV_DEFINED = lib.TPM2_RC_NV_DEFINED
    BAD_CONTEXT = lib.TPM2_RC_BAD_CONTEXT
    CPHASH = lib.TPM2_RC_CPHASH
    PARENT = lib.TPM2_RC_PARENT
    NEEDS_TEST = lib.TPM2_RC_NEEDS_TEST
    NO_RESULT = lib.TPM2_RC_NO_RESULT
    SENSITIVE = lib.TPM2_RC_SENSITIVE
    MAX_FM0 = lib.TPM2_RC_MAX_FM0
    FMT1 = lib.TPM2_RC_FMT1
    ASYMMETRIC = lib.TPM2_RC_ASYMMETRIC
    ATTRIBUTES = lib.TPM2_RC_ATTRIBUTES
    HASH = lib.TPM2_RC_HASH
    VALUE = lib.TPM2_RC_VALUE
    HIERARCHY = lib.TPM2_RC_HIERARCHY
    KEY_SIZE = lib.TPM2_RC_KEY_SIZE
    MGF = lib.TPM2_RC_MGF
    MODE = lib.TPM2_RC_MODE
    TYPE = lib.TPM2_RC_TYPE
    HANDLE = lib.TPM2_RC_HANDLE
    KDF = lib.TPM2_RC_KDF
    RANGE = lib.TPM2_RC_RANGE
    AUTH_FAIL = lib.TPM2_RC_AUTH_FAIL
    NONCE = lib.TPM2_RC_NONCE
    PP = lib.TPM2_RC_PP
    SCHEME = lib.TPM2_RC_SCHEME
    SIZE = lib.TPM2_RC_SIZE
    SYMMETRIC = lib.TPM2_RC_SYMMETRIC
    TAG = lib.TPM2_RC_TAG
    SELECTOR = lib.TPM2_RC_SELECTOR
    INSUFFICIENT = lib.TPM2_RC_INSUFFICIENT
    SIGNATURE = lib.TPM2_RC_SIGNATURE
    KEY = lib.TPM2_RC_KEY
    POLICY_FAIL = lib.TPM2_RC_POLICY_FAIL
    INTEGRITY = lib.TPM2_RC_INTEGRITY
    TICKET = lib.TPM2_RC_TICKET
    BAD_AUTH = lib.TPM2_RC_BAD_AUTH
    EXPIRED = lib.TPM2_RC_EXPIRED
    POLICY_CC = lib.TPM2_RC_POLICY_CC
    BINDING = lib.TPM2_RC_BINDING
    CURVE = lib.TPM2_RC_CURVE
    ECC_POINT = lib.TPM2_RC_ECC_POINT
    WARN = lib.TPM2_RC_WARN
    CONTEXT_GAP = lib.TPM2_RC_CONTEXT_GAP
    OBJECT_MEMORY = lib.TPM2_RC_OBJECT_MEMORY
    SESSION_MEMORY = lib.TPM2_RC_SESSION_MEMORY
    MEMORY = lib.TPM2_RC_MEMORY
    SESSION_HANDLES = lib.TPM2_RC_SESSION_HANDLES
    OBJECT_HANDLES = lib.TPM2_RC_OBJECT_HANDLES
    LOCALITY = lib.TPM2_RC_LOCALITY
    YIELDED = lib.TPM2_RC_YIELDED
    CANCELED = lib.TPM2_RC_CANCELED
    TESTING = lib.TPM2_RC_TESTING
    REFERENCE_H0 = lib.TPM2_RC_REFERENCE_H0
    REFERENCE_H1 = lib.TPM2_RC_REFERENCE_H1
    REFERENCE_H2 = lib.TPM2_RC_REFERENCE_H2
    REFERENCE_H3 = lib.TPM2_RC_REFERENCE_H3
    REFERENCE_H4 = lib.TPM2_RC_REFERENCE_H4
    REFERENCE_H5 = lib.TPM2_RC_REFERENCE_H5
    REFERENCE_H6 = lib.TPM2_RC_REFERENCE_H6
    REFERENCE_S0 = lib.TPM2_RC_REFERENCE_S0
    REFERENCE_S1 = lib.TPM2_RC_REFERENCE_S1
    REFERENCE_S2 = lib.TPM2_RC_REFERENCE_S2
    REFERENCE_S3 = lib.TPM2_RC_REFERENCE_S3
    REFERENCE_S4 = lib.TPM2_RC_REFERENCE_S4
    REFERENCE_S5 = lib.TPM2_RC_REFERENCE_S5
    REFERENCE_S6 = lib.TPM2_RC_REFERENCE_S6
    NV_RATE = lib.TPM2_RC_NV_RATE
    LOCKOUT = lib.TPM2_RC_LOCKOUT
    RETRY = lib.TPM2_RC_RETRY
    NV_UNAVAILABLE = lib.TPM2_RC_NV_UNAVAILABLE
    NOT_USED = lib.TPM2_RC_NOT_USED
    H = lib.TPM2_RC_H
    P = lib.TPM2_RC_P
    S = lib.TPM2_RC_S
    RC1 = lib.TPM2_RC_1
    RC2 = lib.TPM2_RC_2
    RC3 = lib.TPM2_RC_3
    RC4 = lib.TPM2_RC_4
    RC5 = lib.TPM2_RC_5
    RC6 = lib.TPM2_RC_6
    RC7 = lib.TPM2_RC_7
    RC8 = lib.TPM2_RC_8
    RC9 = lib.TPM2_RC_9
    A = lib.TPM2_RC_A
    B = lib.TPM2_RC_B
    C = lib.TPM2_RC_C
    D = lib.TPM2_RC_D
    E = lib.TPM2_RC_E
    F = lib.TPM2_RC_F
    N_MASK = lib.TPM2_RC_N_MASK


@TPM_FRIENDLY_INT._fix_const_type
class TSS2_RC(TPM_BASE_RC):
    RC_LAYER_SHIFT = lib.TSS2_RC_LAYER_SHIFT
    RC_LAYER_MASK = lib.TSS2_RC_LAYER_MASK
    TPM_RC_LAYER = lib.TSS2_TPM_RC_LAYER
    FEATURE_RC_LAYER = lib.TSS2_FEATURE_RC_LAYER
    ESAPI_RC_LAYER = lib.TSS2_ESAPI_RC_LAYER
    SYS_RC_LAYER = lib.TSS2_SYS_RC_LAYER
    MU_RC_LAYER = lib.TSS2_MU_RC_LAYER
    TCTI_RC_LAYER = lib.TSS2_TCTI_RC_LAYER
    RESMGR_RC_LAYER = lib.TSS2_RESMGR_RC_LAYER
    RESMGR_TPM_RC_LAYER = lib.TSS2_RESMGR_TPM_RC_LAYER
    BASE_RC_GENERAL_FAILURE = lib.TSS2_BASE_RC_GENERAL_FAILURE
    BASE_RC_NOT_IMPLEMENTED = lib.TSS2_BASE_RC_NOT_IMPLEMENTED
    BASE_RC_BAD_CONTEXT = lib.TSS2_BASE_RC_BAD_CONTEXT
    BASE_RC_ABI_MISMATCH = lib.TSS2_BASE_RC_ABI_MISMATCH
    BASE_RC_BAD_REFERENCE = lib.TSS2_BASE_RC_BAD_REFERENCE
    BASE_RC_INSUFFICIENT_BUFFER = lib.TSS2_BASE_RC_INSUFFICIENT_BUFFER
    BASE_RC_BAD_SEQUENCE = lib.TSS2_BASE_RC_BAD_SEQUENCE
    BASE_RC_NO_CONNECTION = lib.TSS2_BASE_RC_NO_CONNECTION
    BASE_RC_TRY_AGAIN = lib.TSS2_BASE_RC_TRY_AGAIN
    BASE_RC_IO_ERROR = lib.TSS2_BASE_RC_IO_ERROR
    BASE_RC_BAD_VALUE = lib.TSS2_BASE_RC_BAD_VALUE
    BASE_RC_NOT_PERMITTED = lib.TSS2_BASE_RC_NOT_PERMITTED
    BASE_RC_INVALID_SESSIONS = lib.TSS2_BASE_RC_INVALID_SESSIONS
    BASE_RC_NO_DECRYPT_PARAM = lib.TSS2_BASE_RC_NO_DECRYPT_PARAM
    BASE_RC_NO_ENCRYPT_PARAM = lib.TSS2_BASE_RC_NO_ENCRYPT_PARAM
    BASE_RC_BAD_SIZE = lib.TSS2_BASE_RC_BAD_SIZE
    BASE_RC_MALFORMED_RESPONSE = lib.TSS2_BASE_RC_MALFORMED_RESPONSE
    BASE_RC_INSUFFICIENT_CONTEXT = lib.TSS2_BASE_RC_INSUFFICIENT_CONTEXT
    BASE_RC_INSUFFICIENT_RESPONSE = lib.TSS2_BASE_RC_INSUFFICIENT_RESPONSE
    BASE_RC_INCOMPATIBLE_TCTI = lib.TSS2_BASE_RC_INCOMPATIBLE_TCTI
    BASE_RC_NOT_SUPPORTED = lib.TSS2_BASE_RC_NOT_SUPPORTED
    BASE_RC_BAD_TCTI_STRUCTURE = lib.TSS2_BASE_RC_BAD_TCTI_STRUCTURE
    BASE_RC_MEMORY = lib.TSS2_BASE_RC_MEMORY
    BASE_RC_BAD_TR = lib.TSS2_BASE_RC_BAD_TR
    BASE_RC_MULTIPLE_DECRYPT_SESSIONS = lib.TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS
    BASE_RC_MULTIPLE_ENCRYPT_SESSIONS = lib.TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS
    BASE_RC_RSP_AUTH_FAILED = lib.TSS2_BASE_RC_RSP_AUTH_FAILED
    BASE_RC_NO_CONFIG = lib.TSS2_BASE_RC_NO_CONFIG
    BASE_RC_BAD_PATH = lib.TSS2_BASE_RC_BAD_PATH
    BASE_RC_NOT_DELETABLE = lib.TSS2_BASE_RC_NOT_DELETABLE
    BASE_RC_PATH_ALREADY_EXISTS = lib.TSS2_BASE_RC_PATH_ALREADY_EXISTS
    BASE_RC_KEY_NOT_FOUND = lib.TSS2_BASE_RC_KEY_NOT_FOUND
    BASE_RC_SIGNATURE_VERIFICATION_FAILED = (
        lib.TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED
    )
    BASE_RC_HASH_MISMATCH = lib.TSS2_BASE_RC_HASH_MISMATCH
    BASE_RC_KEY_NOT_DUPLICABLE = lib.TSS2_BASE_RC_KEY_NOT_DUPLICABLE
    BASE_RC_PATH_NOT_FOUND = lib.TSS2_BASE_RC_PATH_NOT_FOUND
    BASE_RC_NO_CERT = lib.TSS2_BASE_RC_NO_CERT
    BASE_RC_NO_PCR = lib.TSS2_BASE_RC_NO_PCR
    BASE_RC_PCR_NOT_RESETTABLE = lib.TSS2_BASE_RC_PCR_NOT_RESETTABLE
    BASE_RC_BAD_TEMPLATE = lib.TSS2_BASE_RC_BAD_TEMPLATE
    BASE_RC_AUTHORIZATION_FAILED = lib.TSS2_BASE_RC_AUTHORIZATION_FAILED
    BASE_RC_AUTHORIZATION_UNKNOWN = lib.TSS2_BASE_RC_AUTHORIZATION_UNKNOWN
    BASE_RC_NV_NOT_READABLE = lib.TSS2_BASE_RC_NV_NOT_READABLE
    BASE_RC_NV_TOO_SMALL = lib.TSS2_BASE_RC_NV_TOO_SMALL
    BASE_RC_NV_NOT_WRITEABLE = lib.TSS2_BASE_RC_NV_NOT_WRITEABLE
    BASE_RC_POLICY_UNKNOWN = lib.TSS2_BASE_RC_POLICY_UNKNOWN
    BASE_RC_NV_WRONG_TYPE = lib.TSS2_BASE_RC_NV_WRONG_TYPE
    BASE_RC_NAME_ALREADY_EXISTS = lib.TSS2_BASE_RC_NAME_ALREADY_EXISTS
    BASE_RC_NO_TPM = lib.TSS2_BASE_RC_NO_TPM
    BASE_RC_BAD_KEY = lib.TSS2_BASE_RC_BAD_KEY
    BASE_RC_NO_HANDLE = lib.TSS2_BASE_RC_NO_HANDLE

    if pkgconfig.installed("tss2-esapi", ">=3.0.0"):
        BASE_RC_NOT_PROVISIONED = lib.TSS2_BASE_RC_NOT_PROVISIONED
        BASE_RC_ALREADY_PROVISIONED = lib.TSS2_BASE_RC_ALREADY_PROVISIONED

    LAYER_IMPLEMENTATION_SPECIFIC_OFFSET = lib.TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET
    LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT = lib.TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT
    RC_SUCCESS = lib.TSS2_RC_SUCCESS
    TCTI_RC_GENERAL_FAILURE = lib.TSS2_TCTI_RC_GENERAL_FAILURE
    TCTI_RC_NOT_IMPLEMENTED = lib.TSS2_TCTI_RC_NOT_IMPLEMENTED
    TCTI_RC_BAD_CONTEXT = lib.TSS2_TCTI_RC_BAD_CONTEXT
    TCTI_RC_ABI_MISMATCH = lib.TSS2_TCTI_RC_ABI_MISMATCH
    TCTI_RC_BAD_REFERENCE = lib.TSS2_TCTI_RC_BAD_REFERENCE
    TCTI_RC_INSUFFICIENT_BUFFER = lib.TSS2_TCTI_RC_INSUFFICIENT_BUFFER
    TCTI_RC_BAD_SEQUENCE = lib.TSS2_TCTI_RC_BAD_SEQUENCE
    TCTI_RC_NO_CONNECTION = lib.TSS2_TCTI_RC_NO_CONNECTION
    TCTI_RC_TRY_AGAIN = lib.TSS2_TCTI_RC_TRY_AGAIN
    TCTI_RC_IO_ERROR = lib.TSS2_TCTI_RC_IO_ERROR
    TCTI_RC_BAD_VALUE = lib.TSS2_TCTI_RC_BAD_VALUE
    TCTI_RC_NOT_PERMITTED = lib.TSS2_TCTI_RC_NOT_PERMITTED
    TCTI_RC_MALFORMED_RESPONSE = lib.TSS2_TCTI_RC_MALFORMED_RESPONSE
    TCTI_RC_NOT_SUPPORTED = lib.TSS2_TCTI_RC_NOT_SUPPORTED
    TCTI_RC_MEMORY = lib.TSS2_TCTI_RC_MEMORY
    SYS_RC_GENERAL_FAILURE = lib.TSS2_SYS_RC_GENERAL_FAILURE
    SYS_RC_ABI_MISMATCH = lib.TSS2_SYS_RC_ABI_MISMATCH
    SYS_RC_BAD_REFERENCE = lib.TSS2_SYS_RC_BAD_REFERENCE
    SYS_RC_INSUFFICIENT_BUFFER = lib.TSS2_SYS_RC_INSUFFICIENT_BUFFER
    SYS_RC_BAD_SEQUENCE = lib.TSS2_SYS_RC_BAD_SEQUENCE
    SYS_RC_BAD_VALUE = lib.TSS2_SYS_RC_BAD_VALUE
    SYS_RC_INVALID_SESSIONS = lib.TSS2_SYS_RC_INVALID_SESSIONS
    SYS_RC_NO_DECRYPT_PARAM = lib.TSS2_SYS_RC_NO_DECRYPT_PARAM
    SYS_RC_NO_ENCRYPT_PARAM = lib.TSS2_SYS_RC_NO_ENCRYPT_PARAM
    SYS_RC_BAD_SIZE = lib.TSS2_SYS_RC_BAD_SIZE
    SYS_RC_MALFORMED_RESPONSE = lib.TSS2_SYS_RC_MALFORMED_RESPONSE
    SYS_RC_INSUFFICIENT_CONTEXT = lib.TSS2_SYS_RC_INSUFFICIENT_CONTEXT
    SYS_RC_INSUFFICIENT_RESPONSE = lib.TSS2_SYS_RC_INSUFFICIENT_RESPONSE
    SYS_RC_INCOMPATIBLE_TCTI = lib.TSS2_SYS_RC_INCOMPATIBLE_TCTI
    SYS_RC_BAD_TCTI_STRUCTURE = lib.TSS2_SYS_RC_BAD_TCTI_STRUCTURE
    MU_RC_GENERAL_FAILURE = lib.TSS2_MU_RC_GENERAL_FAILURE
    MU_RC_BAD_REFERENCE = lib.TSS2_MU_RC_BAD_REFERENCE
    MU_RC_BAD_SIZE = lib.TSS2_MU_RC_BAD_SIZE
    MU_RC_BAD_VALUE = lib.TSS2_MU_RC_BAD_VALUE
    MU_RC_INSUFFICIENT_BUFFER = lib.TSS2_MU_RC_INSUFFICIENT_BUFFER
    ESYS_RC_GENERAL_FAILURE = lib.TSS2_ESYS_RC_GENERAL_FAILURE
    ESYS_RC_NOT_IMPLEMENTED = lib.TSS2_ESYS_RC_NOT_IMPLEMENTED
    ESYS_RC_ABI_MISMATCH = lib.TSS2_ESYS_RC_ABI_MISMATCH
    ESYS_RC_BAD_REFERENCE = lib.TSS2_ESYS_RC_BAD_REFERENCE
    ESYS_RC_INSUFFICIENT_BUFFER = lib.TSS2_ESYS_RC_INSUFFICIENT_BUFFER
    ESYS_RC_BAD_SEQUENCE = lib.TSS2_ESYS_RC_BAD_SEQUENCE
    ESYS_RC_INVALID_SESSIONS = lib.TSS2_ESYS_RC_INVALID_SESSIONS
    ESYS_RC_TRY_AGAIN = lib.TSS2_ESYS_RC_TRY_AGAIN
    ESYS_RC_IO_ERROR = lib.TSS2_ESYS_RC_IO_ERROR
    ESYS_RC_BAD_VALUE = lib.TSS2_ESYS_RC_BAD_VALUE
    ESYS_RC_NO_DECRYPT_PARAM = lib.TSS2_ESYS_RC_NO_DECRYPT_PARAM
    ESYS_RC_NO_ENCRYPT_PARAM = lib.TSS2_ESYS_RC_NO_ENCRYPT_PARAM
    ESYS_RC_BAD_SIZE = lib.TSS2_ESYS_RC_BAD_SIZE
    ESYS_RC_MALFORMED_RESPONSE = lib.TSS2_ESYS_RC_MALFORMED_RESPONSE
    ESYS_RC_INSUFFICIENT_CONTEXT = lib.TSS2_ESYS_RC_INSUFFICIENT_CONTEXT
    ESYS_RC_INSUFFICIENT_RESPONSE = lib.TSS2_ESYS_RC_INSUFFICIENT_RESPONSE
    ESYS_RC_INCOMPATIBLE_TCTI = lib.TSS2_ESYS_RC_INCOMPATIBLE_TCTI
    ESYS_RC_BAD_TCTI_STRUCTURE = lib.TSS2_ESYS_RC_BAD_TCTI_STRUCTURE
    ESYS_RC_MEMORY = lib.TSS2_ESYS_RC_MEMORY
    ESYS_RC_BAD_TR = lib.TSS2_ESYS_RC_BAD_TR
    ESYS_RC_MULTIPLE_DECRYPT_SESSIONS = lib.TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS
    ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS = lib.TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS
    ESYS_RC_RSP_AUTH_FAILED = lib.TSS2_ESYS_RC_RSP_AUTH_FAILED
    if pkgconfig.installed("tss2-fapi", ">=3.0.0"):
        FAPI_RC_GENERAL_FAILURE = lib.TSS2_FAPI_RC_GENERAL_FAILURE
        FAPI_RC_NOT_IMPLEMENTED = lib.TSS2_FAPI_RC_NOT_IMPLEMENTED
        FAPI_RC_BAD_REFERENCE = lib.TSS2_FAPI_RC_BAD_REFERENCE
        FAPI_RC_BAD_SEQUENCE = lib.TSS2_FAPI_RC_BAD_SEQUENCE
        FAPI_RC_IO_ERROR = lib.TSS2_FAPI_RC_IO_ERROR
        FAPI_RC_BAD_VALUE = lib.TSS2_FAPI_RC_BAD_VALUE
        FAPI_RC_NO_DECRYPT_PARAM = lib.TSS2_FAPI_RC_NO_DECRYPT_PARAM
        FAPI_RC_NO_ENCRYPT_PARAM = lib.TSS2_FAPI_RC_NO_ENCRYPT_PARAM
        FAPI_RC_MEMORY = lib.TSS2_FAPI_RC_MEMORY
        FAPI_RC_BAD_CONTEXT = lib.TSS2_FAPI_RC_BAD_CONTEXT
        FAPI_RC_NO_CONFIG = lib.TSS2_FAPI_RC_NO_CONFIG
        FAPI_RC_BAD_PATH = lib.TSS2_FAPI_RC_BAD_PATH
        FAPI_RC_NOT_DELETABLE = lib.TSS2_FAPI_RC_NOT_DELETABLE
        FAPI_RC_PATH_ALREADY_EXISTS = lib.TSS2_FAPI_RC_PATH_ALREADY_EXISTS
        FAPI_RC_KEY_NOT_FOUND = lib.TSS2_FAPI_RC_KEY_NOT_FOUND
        FAPI_RC_SIGNATURE_VERIFICATION_FAILED = (
            lib.TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED
        )
        FAPI_RC_HASH_MISMATCH = lib.TSS2_FAPI_RC_HASH_MISMATCH
        FAPI_RC_KEY_NOT_DUPLICABLE = lib.TSS2_FAPI_RC_KEY_NOT_DUPLICABLE
        FAPI_RC_PATH_NOT_FOUND = lib.TSS2_FAPI_RC_PATH_NOT_FOUND
        FAPI_RC_NO_CERT = lib.TSS2_FAPI_RC_NO_CERT
        FAPI_RC_NO_PCR = lib.TSS2_FAPI_RC_NO_PCR
        FAPI_RC_PCR_NOT_RESETTABLE = lib.TSS2_FAPI_RC_PCR_NOT_RESETTABLE
        FAPI_RC_BAD_TEMPLATE = lib.TSS2_FAPI_RC_BAD_TEMPLATE
        FAPI_RC_AUTHORIZATION_FAILED = lib.TSS2_FAPI_RC_AUTHORIZATION_FAILED
        FAPI_RC_AUTHORIZATION_UNKNOWN = lib.TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN
        FAPI_RC_NV_NOT_READABLE = lib.TSS2_FAPI_RC_NV_NOT_READABLE
        FAPI_RC_NV_TOO_SMALL = lib.TSS2_FAPI_RC_NV_TOO_SMALL
        FAPI_RC_NV_NOT_WRITEABLE = lib.TSS2_FAPI_RC_NV_NOT_WRITEABLE
        FAPI_RC_POLICY_UNKNOWN = lib.TSS2_FAPI_RC_POLICY_UNKNOWN
        FAPI_RC_NV_WRONG_TYPE = lib.TSS2_FAPI_RC_NV_WRONG_TYPE
        FAPI_RC_NAME_ALREADY_EXISTS = lib.TSS2_FAPI_RC_NAME_ALREADY_EXISTS
        FAPI_RC_NO_TPM = lib.TSS2_FAPI_RC_NO_TPM
        FAPI_RC_TRY_AGAIN = lib.TSS2_FAPI_RC_TRY_AGAIN
        FAPI_RC_BAD_KEY = lib.TSS2_FAPI_RC_BAD_KEY
        FAPI_RC_NO_HANDLE = lib.TSS2_FAPI_RC_NO_HANDLE
        FAPI_RC_NOT_PROVISIONED = lib.TSS2_FAPI_RC_NOT_PROVISIONED
        FAPI_RC_ALREADY_PROVISIONED = lib.TSS2_FAPI_RC_ALREADY_PROVISIONED


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_EO(TPM_FRIENDLY_INT):
    EQ = lib.TPM2_EO_EQ
    NEQ = lib.TPM2_EO_NEQ
    SIGNED_GT = lib.TPM2_EO_SIGNED_GT
    UNSIGNED_GT = lib.TPM2_EO_UNSIGNED_GT
    SIGNED_LT = lib.TPM2_EO_SIGNED_LT
    UNSIGNED_LT = lib.TPM2_EO_UNSIGNED_LT
    SIGNED_GE = lib.TPM2_EO_SIGNED_GE
    UNSIGNED_GE = lib.TPM2_EO_UNSIGNED_GE
    SIGNED_LE = lib.TPM2_EO_SIGNED_LE
    UNSIGNED_LE = lib.TPM2_EO_UNSIGNED_LE
    BITSET = lib.TPM2_EO_BITSET
    BITCLEAR = lib.TPM2_EO_BITCLEAR


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_ST(TPM_FRIENDLY_INT):
    RSP_COMMAND = lib.TPM2_ST_RSP_COMMAND
    NULL = lib.TPM2_ST_NULL
    NO_SESSIONS = lib.TPM2_ST_NO_SESSIONS
    SESSIONS = lib.TPM2_ST_SESSIONS
    ATTEST_NV = lib.TPM2_ST_ATTEST_NV
    ATTEST_COMMAND_AUDIT = lib.TPM2_ST_ATTEST_COMMAND_AUDIT
    ATTEST_SESSION_AUDIT = lib.TPM2_ST_ATTEST_SESSION_AUDIT
    ATTEST_CERTIFY = lib.TPM2_ST_ATTEST_CERTIFY
    ATTEST_QUOTE = lib.TPM2_ST_ATTEST_QUOTE
    ATTEST_TIME = lib.TPM2_ST_ATTEST_TIME
    ATTEST_CREATION = lib.TPM2_ST_ATTEST_CREATION
    CREATION = lib.TPM2_ST_CREATION
    VERIFIED = lib.TPM2_ST_VERIFIED
    AUTH_SECRET = lib.TPM2_ST_AUTH_SECRET
    HASHCHECK = lib.TPM2_ST_HASHCHECK
    AUTH_SIGNED = lib.TPM2_ST_AUTH_SIGNED
    FU_MANIFEST = lib.TPM2_ST_FU_MANIFEST


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_SU(TPM_FRIENDLY_INT):
    CLEAR = lib.TPM2_SU_CLEAR
    STATE = lib.TPM2_SU_STATE


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_SE(TPM_FRIENDLY_INT):
    HMAC = lib.TPM2_SE_HMAC
    POLICY = lib.TPM2_SE_POLICY
    TRIAL = lib.TPM2_SE_TRIAL


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_CAP(TPM_FRIENDLY_INT):
    FIRST = lib.TPM2_CAP_FIRST
    ALGS = lib.TPM2_CAP_ALGS
    HANDLES = lib.TPM2_CAP_HANDLES
    COMMANDS = lib.TPM2_CAP_COMMANDS
    PP_COMMANDS = lib.TPM2_CAP_PP_COMMANDS
    AUDIT_COMMANDS = lib.TPM2_CAP_AUDIT_COMMANDS
    PCRS = lib.TPM2_CAP_PCRS
    TPM_PROPERTIES = lib.TPM2_CAP_TPM_PROPERTIES
    PCR_PROPERTIES = lib.TPM2_CAP_PCR_PROPERTIES
    ECC_CURVES = lib.TPM2_CAP_ECC_CURVES
    LAST = lib.TPM2_CAP_LAST
    VENDOR_PROPERTY = lib.TPM2_CAP_VENDOR_PROPERTY


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT(TPM_FRIENDLY_INT):
    NONE = lib.TPM2_PT_NONE
    GROUP = lib.TPM2_PT_GROUP
    FIXED = lib.TPM2_PT_FIXED
    LOCKOUT_COUNTER = lib.TPM2_PT_LOCKOUT_COUNTER
    LEVEL = lib.TPM2_PT_LEVEL
    REVISION = lib.TPM2_PT_REVISION
    DAY_OF_YEAR = lib.TPM2_PT_DAY_OF_YEAR
    YEAR = lib.TPM2_PT_YEAR
    MANUFACTURER = lib.TPM2_PT_MANUFACTURER
    FAMILY_INDICATOR = lib.TPM2_PT_FAMILY_INDICATOR
    INPUT_BUFFER = lib.TPM2_PT_INPUT_BUFFER
    ACTIVE_SESSIONS_MAX = lib.TPM2_PT_ACTIVE_SESSIONS_MAX
    CONTEXT_GAP_MAX = lib.TPM2_PT_CONTEXT_GAP_MAX
    MEMORY = lib.TPM2_PT_MEMORY
    CLOCK_UPDATE = lib.TPM2_PT_CLOCK_UPDATE
    ORDERLY_COUNT = lib.TPM2_PT_ORDERLY_COUNT
    MAX_COMMAND_SIZE = lib.TPM2_PT_MAX_COMMAND_SIZE
    MAX_RESPONSE_SIZE = lib.TPM2_PT_MAX_RESPONSE_SIZE
    MAX_DIGEST = lib.TPM2_PT_MAX_DIGEST
    MAX_OBJECT_CONTEXT = lib.TPM2_PT_MAX_OBJECT_CONTEXT
    MAX_SESSION_CONTEXT = lib.TPM2_PT_MAX_SESSION_CONTEXT
    SPLIT_MAX = lib.TPM2_PT_SPLIT_MAX
    TOTAL_COMMANDS = lib.TPM2_PT_TOTAL_COMMANDS
    VENDOR_COMMANDS = lib.TPM2_PT_VENDOR_COMMANDS
    MODES = lib.TPM2_PT_MODES
    VAR = lib.TPM2_PT_VAR
    PERMANENT = lib.TPM2_PT_PERMANENT
    STARTUP_CLEAR = lib.TPM2_PT_STARTUP_CLEAR
    LIBRARY_COMMANDS = lib.TPM2_PT_LIBRARY_COMMANDS
    ALGORITHM_SET = lib.TPM2_PT_ALGORITHM_SET
    LOADED_CURVES = lib.TPM2_PT_LOADED_CURVES
    MAX_AUTH_FAIL = lib.TPM2_PT_MAX_AUTH_FAIL
    LOCKOUT_INTERVAL = lib.TPM2_PT_LOCKOUT_INTERVAL
    LOCKOUT_RECOVERY = lib.TPM2_PT_LOCKOUT_RECOVERY


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_VENDOR(TPM_FRIENDLY_INT):
    STRING_1 = lib.TPM2_PT_VENDOR_STRING_1
    STRING_2 = lib.TPM2_PT_VENDOR_STRING_2
    STRING_3 = lib.TPM2_PT_VENDOR_STRING_3
    STRING_4 = lib.TPM2_PT_VENDOR_STRING_4
    TPM_TYPE = lib.TPM2_PT_VENDOR_TPM_TYPE


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_FIRMWARE(TPM_FRIENDLY_INT):
    VERSION_1 = lib.TPM2_PT_FIRMWARE_VERSION_1
    VERSION_2 = lib.TPM2_PT_FIRMWARE_VERSION_2


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_HR(TPM_FRIENDLY_INT):
    LOADED_MIN = lib.TPM2_PT_HR_LOADED_MIN
    LOADED = lib.TPM2_PT_HR_LOADED
    LOADED_AVAIL = lib.TPM2_PT_HR_LOADED_AVAIL
    ACTIVE = lib.TPM2_PT_HR_ACTIVE
    ACTIVE_AVAIL = lib.TPM2_PT_HR_ACTIVE_AVAIL
    TRANSIENT_AVAIL = lib.TPM2_PT_HR_TRANSIENT_AVAIL
    PERSISTENT_AVAIL = lib.TPM2_PT_HR_PERSISTENT_AVAIL
    TRANSIENT_MIN = lib.TPM2_PT_HR_TRANSIENT_MIN
    PERSISTENT_MIN = lib.TPM2_PT_HR_PERSISTENT_MIN


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_NV(TPM_FRIENDLY_INT):
    COUNTERS_MAX = lib.TPM2_PT_NV_COUNTERS_MAX
    INDEX_MAX = lib.TPM2_PT_NV_INDEX_MAX
    BUFFER_MAX = lib.TPM2_PT_NV_BUFFER_MAX
    COUNTERS = lib.TPM2_PT_NV_COUNTERS
    COUNTERS_AVAIL = lib.TPM2_PT_NV_COUNTERS_AVAIL
    WRITE_RECOVERY = lib.TPM2_PT_NV_WRITE_RECOVERY


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_CONTEXT(TPM_FRIENDLY_INT):
    HASH = lib.TPM2_PT_CONTEXT_HASH
    SYM = lib.TPM2_PT_CONTEXT_SYM
    SYM_SIZE = lib.TPM2_PT_CONTEXT_SYM_SIZE


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_PS(TPM_FRIENDLY_INT):
    FAMILY_INDICATOR = lib.TPM2_PT_PS_FAMILY_INDICATOR
    LEVEL = lib.TPM2_PT_PS_LEVEL
    REVISION = lib.TPM2_PT_PS_REVISION
    DAY_OF_YEAR = lib.TPM2_PT_PS_DAY_OF_YEAR
    YEAR = lib.TPM2_PT_PS_YEAR


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_AUDIT(TPM_FRIENDLY_INT):
    COUNTER_0 = lib.TPM2_PT_AUDIT_COUNTER_0
    COUNTER_1 = lib.TPM2_PT_AUDIT_COUNTER_1


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PT_PCR(TPM_FRIENDLY_INT):
    FIRST = lib.TPM2_PT_TPM2_PCR_FIRST
    SAVE = lib.TPM2_PT_PCR_SAVE
    EXTEND_L0 = lib.TPM2_PT_PCR_EXTEND_L0
    RESET_L0 = lib.TPM2_PT_PCR_RESET_L0
    EXTEND_L1 = lib.TPM2_PT_PCR_EXTEND_L1
    RESET_L1 = lib.TPM2_PT_PCR_RESET_L1
    EXTEND_L2 = lib.TPM2_PT_PCR_EXTEND_L2
    RESET_L2 = lib.TPM2_PT_PCR_RESET_L2
    EXTEND_L3 = lib.TPM2_PT_PCR_EXTEND_L3
    RESET_L3 = lib.TPM2_PT_PCR_RESET_L3
    EXTEND_L4 = lib.TPM2_PT_PCR_EXTEND_L4
    RESET_L4 = lib.TPM2_PT_PCR_RESET_L4
    NO_INCREMENT = lib.TPM2_PT_PCR_NO_INCREMENT
    DRTM_RESET = lib.TPM2_PT_PCR_DRTM_RESET
    POLICY = lib.TPM2_PT_PCR_POLICY
    AUTH = lib.TPM2_PT_PCR_AUTH
    LAST = lib.TPM2_PT_TPM2_PCR_LAST
    COUNT = lib.TPM2_PT_PCR_COUNT
    SELECT_MIN = lib.TPM2_PT_PCR_SELECT_MIN


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_PS(TPM_FRIENDLY_INT):
    MAIN = lib.TPM2_PS_MAIN
    PC = lib.TPM2_PS_PC
    PDA = lib.TPM2_PS_PDA
    CELL_PHONE = lib.TPM2_PS_CELL_PHONE
    SERVER = lib.TPM2_PS_SERVER
    PERIPHERAL = lib.TPM2_PS_PERIPHERAL
    TSS = lib.TPM2_PS_TSS
    STORAGE = lib.TPM2_PS_STORAGE
    AUTHENTICATION = lib.TPM2_PS_AUTHENTICATION
    EMBEDDED = lib.TPM2_PS_EMBEDDED
    HARDCOPY = lib.TPM2_PS_HARDCOPY
    INFRASTRUCTURE = lib.TPM2_PS_INFRASTRUCTURE
    VIRTUALIZATION = lib.TPM2_PS_VIRTUALIZATION
    TNC = lib.TPM2_PS_TNC
    MULTI_TENANT = lib.TPM2_PS_MULTI_TENANT
    TC = lib.TPM2_PS_TC


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_HT(TPM_FRIENDLY_INT):
    PCR = lib.TPM2_HT_PCR
    NV_INDEX = lib.TPM2_HT_NV_INDEX
    HMAC_SESSION = lib.TPM2_HT_HMAC_SESSION
    LOADED_SESSION = lib.TPM2_HT_LOADED_SESSION
    POLICY_SESSION = lib.TPM2_HT_POLICY_SESSION
    SAVED_SESSION = lib.TPM2_HT_SAVED_SESSION
    PERMANENT = lib.TPM2_HT_PERMANENT
    TRANSIENT = lib.TPM2_HT_TRANSIENT
    PERSISTENT = lib.TPM2_HT_PERSISTENT


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_SESSION(TPM_FRIENDLY_INT):
    CONTINUESESSION = lib.TPMA_SESSION_CONTINUESESSION
    AUDITEXCLUSIVE = lib.TPMA_SESSION_AUDITEXCLUSIVE
    AUDITRESET = lib.TPMA_SESSION_AUDITRESET
    DECRYPT = lib.TPMA_SESSION_DECRYPT
    ENCRYPT = lib.TPMA_SESSION_ENCRYPT
    AUDIT = lib.TPMA_SESSION_AUDIT


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_LOCALITY(TPM_FRIENDLY_INT):
    ZERO = lib.TPMA_LOCALITY_TPM2_LOC_ZERO
    ONE = lib.TPMA_LOCALITY_TPM2_LOC_ONE
    TWO = lib.TPMA_LOCALITY_TPM2_LOC_TWO
    THREE = lib.TPMA_LOCALITY_TPM2_LOC_THREE
    FOUR = lib.TPMA_LOCALITY_TPM2_LOC_FOUR
    EXTENDED_MASK = lib.TPMA_LOCALITY_EXTENDED_MASK
    EXTENDED_SHIFT = lib.TPMA_LOCALITY_EXTENDED_SHIFT

    @classmethod
    def create_extended(cls, value):
        x = (1 << cls.EXTENDED_SHIFT) + value
        if x > 255:
            raise ValueError("Extended Localities must be less than 256")
        return x


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_NT(TPM_FRIENDLY_INT):
    ORDINARY = lib.TPM2_NT_ORDINARY
    COUNTER = lib.TPM2_NT_COUNTER
    BITS = lib.TPM2_NT_BITS
    EXTEND = lib.TPM2_NT_EXTEND
    PIN_FAIL = lib.TPM2_NT_PIN_FAIL
    PIN_PASS = lib.TPM2_NT_PIN_PASS


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_HR(TPM_FRIENDLY_INT):
    HANDLE_MASK = lib.TPM2_HR_HANDLE_MASK
    RANGE_MASK = lib.TPM2_HR_RANGE_MASK
    SHIFT = lib.TPM2_HR_SHIFT
    PCR = lib.TPM2_HR_PCR
    HMAC_SESSION = lib.TPM2_HR_HMAC_SESSION
    POLICY_SESSION = lib.TPM2_HR_POLICY_SESSION
    TRANSIENT = lib.TPM2_HR_TRANSIENT
    PERSISTENT = lib.TPM2_HR_PERSISTENT
    NV_INDEX = lib.TPM2_HR_NV_INDEX
    PERMANENT = lib.TPM2_HR_PERMANENT


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_HC(TPM_FRIENDLY_INT):
    HR_HANDLE_MASK = lib.TPM2_HR_HANDLE_MASK
    HR_RANGE_MASK = lib.TPM2_HR_RANGE_MASK
    HR_SHIFT = lib.TPM2_HR_SHIFT
    HR_PCR = lib.TPM2_HR_PCR
    HR_HMAC_SESSION = lib.TPM2_HR_HMAC_SESSION
    HR_POLICY_SESSION = lib.TPM2_HR_POLICY_SESSION
    HR_TRANSIENT = lib.TPM2_HR_TRANSIENT
    HR_PERSISTENT = lib.TPM2_HR_PERSISTENT
    HR_NV_INDEX = lib.TPM2_HR_NV_INDEX
    HR_PERMANENT = lib.TPM2_HR_PERMANENT
    PCR_FIRST = lib.TPM2_PCR_FIRST
    PCR_LAST = lib.TPM2_PCR_LAST
    HMAC_SESSION_FIRST = lib.TPM2_HMAC_SESSION_FIRST
    HMAC_SESSION_LAST = lib.TPM2_HMAC_SESSION_LAST
    LOADED_SESSION_FIRST = lib.TPM2_LOADED_SESSION_FIRST
    LOADED_SESSION_LAST = lib.TPM2_LOADED_SESSION_LAST
    POLICY_SESSION_FIRST = lib.TPM2_POLICY_SESSION_FIRST
    POLICY_SESSION_LAST = lib.TPM2_POLICY_SESSION_LAST
    TRANSIENT_FIRST = lib.TPM2_TRANSIENT_FIRST
    ACTIVE_SESSION_FIRST = lib.TPM2_ACTIVE_SESSION_FIRST
    ACTIVE_SESSION_LAST = lib.TPM2_ACTIVE_SESSION_LAST
    TRANSIENT_LAST = lib.TPM2_TRANSIENT_LAST
    PERSISTENT_FIRST = lib.TPM2_PERSISTENT_FIRST
    PERSISTENT_LAST = lib.TPM2_PERSISTENT_LAST
    PLATFORM_PERSISTENT = lib.TPM2_PLATFORM_PERSISTENT
    NV_INDEX_FIRST = lib.TPM2_NV_INDEX_FIRST
    NV_INDEX_LAST = lib.TPM2_NV_INDEX_LAST
    PERMANENT_FIRST = lib.TPM2_PERMANENT_FIRST
    PERMANENT_LAST = lib.TPM2_PERMANENT_LAST


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_CLOCK(TPM_FRIENDLY_INT):
    COARSE_SLOWER = lib.TPM2_CLOCK_COARSE_SLOWER
    MEDIUM_SLOWER = lib.TPM2_CLOCK_MEDIUM_SLOWER
    FINE_SLOWER = lib.TPM2_CLOCK_FINE_SLOWER
    NO_CHANGE = lib.TPM2_CLOCK_NO_CHANGE
    FINE_FASTER = lib.TPM2_CLOCK_FINE_FASTER
    MEDIUM_FASTER = lib.TPM2_CLOCK_MEDIUM_FASTER
    COARSE_FASTER = lib.TPM2_CLOCK_COARSE_FASTER


TPM2_CLOCK_ADJUST = TPM2_CLOCK


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_NV(TPMA_FRIENDLY_INTLIST):

    _FIXUP_MAP = {"NODA": "NO_DA"}
    _MASKS = ((lib.TPMA_NV_TPM2_NT_MASK, lib.TPMA_NV_TPM2_NT_SHIFT, "nt"),)

    PPWRITE = lib.TPMA_NV_PPWRITE
    OWNERWRITE = lib.TPMA_NV_OWNERWRITE
    AUTHWRITE = lib.TPMA_NV_AUTHWRITE
    POLICYWRITE = lib.TPMA_NV_POLICYWRITE
    TPM2_NT_MASK = lib.TPMA_NV_TPM2_NT_MASK
    TPM2_NT_SHIFT = lib.TPMA_NV_TPM2_NT_SHIFT
    POLICY_DELETE = lib.TPMA_NV_POLICY_DELETE
    WRITELOCKED = lib.TPMA_NV_WRITELOCKED
    WRITEALL = lib.TPMA_NV_WRITEALL
    WRITEDEFINE = lib.TPMA_NV_WRITEDEFINE
    WRITE_STCLEAR = lib.TPMA_NV_WRITE_STCLEAR
    GLOBALLOCK = lib.TPMA_NV_GLOBALLOCK
    PPREAD = lib.TPMA_NV_PPREAD
    OWNERREAD = lib.TPMA_NV_OWNERREAD
    AUTHREAD = lib.TPMA_NV_AUTHREAD
    POLICYREAD = lib.TPMA_NV_POLICYREAD
    NO_DA = lib.TPMA_NV_NO_DA
    ORDERLY = lib.TPMA_NV_ORDERLY
    CLEAR_STCLEAR = lib.TPMA_NV_CLEAR_STCLEAR
    READLOCKED = lib.TPMA_NV_READLOCKED
    WRITTEN = lib.TPMA_NV_WRITTEN
    PLATFORMCREATE = lib.TPMA_NV_PLATFORMCREATE
    READ_STCLEAR = lib.TPMA_NV_READ_STCLEAR

    @property
    def nt(self) -> TPM2_NT:
        """TPM2_NT: The type of the NV area"""
        return TPM2_NT((self & self.TPM2_NT_MASK) >> self.TPM2_NT_SHIFT)


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_CC(TPMA_FRIENDLY_INTLIST):
    _MASKS = (
        (lib.TPMA_CC_COMMANDINDEX_MASK, lib.TPMA_CC_COMMANDINDEX_SHIFT, "commandindex"),
        (lib.TPMA_CC_CHANDLES_MASK, lib.TPMA_CC_CHANDLES_SHIFT, "chandles"),
    )
    COMMANDINDEX_MASK = lib.TPMA_CC_COMMANDINDEX_MASK
    COMMANDINDEX_SHIFT = lib.TPMA_CC_COMMANDINDEX_SHIFT
    NV = lib.TPMA_CC_NV
    EXTENSIVE = lib.TPMA_CC_EXTENSIVE
    FLUSHED = lib.TPMA_CC_FLUSHED
    CHANDLES_MASK = lib.TPMA_CC_CHANDLES_MASK
    CHANDLES_SHIFT = lib.TPMA_CC_CHANDLES_SHIFT
    RHANDLE = lib.TPMA_CC_RHANDLE
    V = lib.TPMA_CC_V
    RES_MASK = lib.TPMA_CC_RES_MASK
    RES_SHIFT = lib.TPMA_CC_RES_SHIFT

    @property
    def commandindex(self) -> int:
        """int: The command index"""
        return self & self.COMMANDINDEX_MASK

    @property
    def chandles(self) -> int:
        """int: The number of handles in the handle area"""
        return (self & self.CHANDLES_MASK) >> self.CHANDLES_SHIFT


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_OBJECT(TPMA_FRIENDLY_INTLIST):
    FIXEDTPM = lib.TPMA_OBJECT_FIXEDTPM
    STCLEAR = lib.TPMA_OBJECT_STCLEAR
    FIXEDPARENT = lib.TPMA_OBJECT_FIXEDPARENT
    SENSITIVEDATAORIGIN = lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
    USERWITHAUTH = lib.TPMA_OBJECT_USERWITHAUTH
    ADMINWITHPOLICY = lib.TPMA_OBJECT_ADMINWITHPOLICY
    NODA = lib.TPMA_OBJECT_NODA
    ENCRYPTEDDUPLICATION = lib.TPMA_OBJECT_ENCRYPTEDDUPLICATION
    RESTRICTED = lib.TPMA_OBJECT_RESTRICTED
    DECRYPT = lib.TPMA_OBJECT_DECRYPT
    SIGN_ENCRYPT = lib.TPMA_OBJECT_SIGN_ENCRYPT

    DEFAULT_TPM2_TOOLS_CREATE_ATTRS = (
        lib.TPMA_OBJECT_DECRYPT
        | lib.TPMA_OBJECT_SIGN_ENCRYPT
        | lib.TPMA_OBJECT_FIXEDTPM
        | lib.TPMA_OBJECT_FIXEDPARENT
        | lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
        | lib.TPMA_OBJECT_USERWITHAUTH
    )

    DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS = (
        lib.TPMA_OBJECT_RESTRICTED
        | lib.TPMA_OBJECT_DECRYPT
        | lib.TPMA_OBJECT_FIXEDTPM
        | lib.TPMA_OBJECT_FIXEDPARENT
        | lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
        | lib.TPMA_OBJECT_USERWITHAUTH
    )

    _FIXUP_MAP = {
        "SIGN": "SIGN_ENCRYPT",
        "ENCRYPT": "SIGN_ENCRYPT",
    }


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_ALGORITHM(TPM_FRIENDLY_INT):
    ASYMMETRIC = lib.TPMA_ALGORITHM_ASYMMETRIC
    SYMMETRIC = lib.TPMA_ALGORITHM_SYMMETRIC
    HASH = lib.TPMA_ALGORITHM_HASH
    OBJECT = lib.TPMA_ALGORITHM_OBJECT
    SIGNING = lib.TPMA_ALGORITHM_SIGNING
    ENCRYPTING = lib.TPMA_ALGORITHM_ENCRYPTING
    METHOD = lib.TPMA_ALGORITHM_METHOD


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_PERMANENT(TPM_FRIENDLY_INT):
    OWNERAUTHSET = lib.TPMA_PERMANENT_OWNERAUTHSET
    ENDORSEMENTAUTHSET = lib.TPMA_PERMANENT_ENDORSEMENTAUTHSET
    LOCKOUTAUTHSET = lib.TPMA_PERMANENT_LOCKOUTAUTHSET
    DISABLECLEAR = lib.TPMA_PERMANENT_DISABLECLEAR
    INLOCKOUT = lib.TPMA_PERMANENT_INLOCKOUT
    TPMGENERATEDEPS = lib.TPMA_PERMANENT_TPMGENERATEDEPS


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_STARTUP(TPM_FRIENDLY_INT):
    CLEAR_PHENABLE = lib.TPMA_STARTUP_CLEAR_PHENABLE
    CLEAR_SHENABLE = lib.TPMA_STARTUP_CLEAR_SHENABLE
    CLEAR_EHENABLE = lib.TPMA_STARTUP_CLEAR_EHENABLE
    CLEAR_PHENABLENV = lib.TPMA_STARTUP_CLEAR_PHENABLENV
    CLEAR_ORDERLY = lib.TPMA_STARTUP_CLEAR_ORDERLY


@TPM_FRIENDLY_INT._fix_const_type
class TPMA_MEMORY(TPM_FRIENDLY_INT):
    SHAREDRAM = lib.TPMA_MEMORY_SHAREDRAM
    SHAREDNV = lib.TPMA_MEMORY_SHAREDNV
    OBJECTCOPIEDTORAM = lib.TPMA_MEMORY_OBJECTCOPIEDTORAM


@TPM_FRIENDLY_INT._fix_const_type
class TPM2_MAX(TPM_FRIENDLY_INT):
    DIGEST_BUFFER = lib.TPM2_MAX_DIGEST_BUFFER
    NV_BUFFER_SIZE = lib.TPM2_MAX_NV_BUFFER_SIZE
    PCRS = lib.TPM2_MAX_PCRS
    ALG_LIST_SIZE = lib.TPM2_MAX_ALG_LIST_SIZE
    CAP_CC = lib.TPM2_MAX_CAP_CC
    CAP_BUFFER = lib.TPM2_MAX_CAP_BUFFER
    CONTEXT_SIZE = lib.TPM2_MAX_CONTEXT_SIZE


#
# We specifically keep these constants around even when FAPI is missing so they may be used
# without conditional worry and we DONT use lib prefix here because the constants are only
# present if FAPI is installed. So just use the values directly.
#
@TPM_FRIENDLY_INT._fix_const_type
class FAPI_ESYSBLOB(TPM_FRIENDLY_INT):
    CONTEXTLOAD = 1
    DESERIALIZE = 2
