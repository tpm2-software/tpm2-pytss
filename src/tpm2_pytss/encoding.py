from binascii import hexlify, unhexlify
from typing import Any, Union, List, Dict, Tuple
from ._libtpm2_pytss import ffi
from .internal.crypto import _get_digest_size
from .constants import (
    TPM_FRIENDLY_INT,
    TPMA_FRIENDLY_INTLIST,
    TPM2_CAP,
    TPM2_ST,
    TPM2_ALG,
    TPMA_NV,
    TPMA_CC,
    TPM2_NT,
    TPMA_LOCALITY,
    TPMA_ALGORITHM,
    TPM2_CC,
    TPM2_PT,
    TPM2_PT_VENDOR,
    TPMA_MODES,
    TPM2_PT_FIRMWARE,
    TPM2_PT_HR,
    TPM2_PT_NV,
    TPM2_PT_CONTEXT,
    TPM2_PT_PS,
    TPM2_PT_AUDIT,
    TPM2_PT_PCR,
    TPMA_PERMANENT,
    TPMA_STARTUP,
    TPM2_ECC,
    TPM2_RH,
    TPMA_OBJECT,
    TPMA_SESSION,
)
from .types import (
    TPM_OBJECT,
    TPM2B_SIMPLE_OBJECT,
    TPML_OBJECT,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE,
    TPMT_PUBLIC,
    TPMT_SENSITIVE,
    TPMT_KDF_SCHEME,
    TPMT_ASYM_SCHEME,
    TPMT_RSA_SCHEME,
    TPMT_ECC_SCHEME,
    TPMT_SYM_DEF_OBJECT,
    TPMT_KEYEDHASH_SCHEME,
    TPMT_HA,
    TPMS_CAPABILITY_DATA,
    TPMS_ATTEST,
    TPMT_SIGNATURE,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_ECC_POINT,
    TPM2B_NV_PUBLIC,
    TPM2B_CREATION_DATA,
    TPMT_SYM_DEF,
    TPMT_SIG_SCHEME,
    TPMT_RSA_DECRYPT,
    TPMT_PUBLIC_PARMS,
    TPMS_NV_PUBLIC,
    TPMS_ALG_PROPERTY,
    TPML_PCR_SELECTION,
    TPMS_PCR_SELECTION,
    TPML_TAGGED_TPM_PROPERTY,
    TPML_ALG_PROPERTY,
    TPML_CCA,
    TPMS_TAGGED_PROPERTY,
    TPML_ECC_CURVE,
    TPML_HANDLE,
    TPMS_CLOCK_INFO,
    TPMS_CONTEXT,
    TPM2_HANDLE,
    TPM2B_DIGEST,
    TPML_DIGEST,
    TPML_DIGEST_VALUES,
    TPMU_HA,
    TPML_ALG,
    TPM2B_NAME,
    TPMS_NV_PIN_COUNTER_PARAMETERS,
)
import yaml
import collections.abc


class base_encdec(object):
    """Base encoder/decoder for TPM types

    Args:
        strict (bool): If a exception should be raised for unknown fields during decoding, defaults to False.
        case_insensitive (bool): If field names should be case insensitive during decoding, defaults to False.
    """

    def __init__(self, strict: bool = False, case_insensitive: bool = False):
        self._strict = strict
        self._case_insensitive = case_insensitive

    def _is_union(self, val):
        if not hasattr(val, "_cdata"):
            return False
        to = ffi.typeof(val._cdata)
        if to.kind == "pointer":
            to = to.item
        if to.kind == "union":
            return True
        return False

    def _get_complex_field(self, val):
        for fn in dir(val._cdata):
            if fn != "size":
                return getattr(val, fn)
        return None

    def _set_complex_field(self, dst, f):
        for fn in dir(dst._cdata):
            if fn != "size":
                setattr(dst, fn, f)
                return
        raise ValueError(f"no complex field found for {dst.__class__.__name__}")

    def _get_element_type(self, dst):
        return type(dst[0])

    def _get_by_selector(self, val, field):
        if isinstance(val, TPMS_CAPABILITY_DATA):
            if val.capability == TPM2_CAP.ALGS:
                return val.data.algorithms
            if val.capability == TPM2_CAP.HANDLES:
                return val.data.handles
            if val.capability == TPM2_CAP.COMMANDS:
                return val.data.command
            if val.capability == TPM2_CAP.PP_COMMANDS:
                return val.data.ppCommands
            if val.capability == TPM2_CAP.AUDIT_COMMANDS:
                return val.data.auditCommands
            if val.capability == TPM2_CAP.PCRS:
                return val.data.assignedPCR
            if val.capability == TPM2_CAP.TPM_PROPERTIES:
                return val.data.tpmProperties
            if val.capability == TPM2_CAP.PCR_PROPERTIES:
                return val.data.pcrProperties
            if val.capability == TPM2_CAP.ECC_CURVES:
                return val.data.eccCurves
        elif isinstance(val, TPMS_ATTEST):
            if val.type == TPM2_ST.ATTEST_CERTIFY:
                return val.attested.certify
            if val.type == TPM2_ST.ATTEST_CREATION:
                return val.attested.creation
            if val.type == TPM2_ST.ATTEST_QUOTE:
                return val.attested.quote
            if val.type == TPM2_ST.ATTEST_COMMAND_AUDIT:
                return val.attested.commandAudit
            if val.type == TPM2_ST.ATTEST_SESSION_AUDIT:
                return val.attested.sessionAudit
            if val.type == TPM2_ST.ATTEST_TIME:
                return val.attested.time
            if val.type == TPM2_ST.ATTEST_NV:
                return val.attested.nv
        elif (
            isinstance(val, (TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT)) and field == "keyBits"
        ):
            if val.algorithm == TPM2_ALG.XOR:
                return val.keyBits.exclusiveOr
            elif val.algorithm in (TPM2_ALG.NULL, TPM2_ALG.ERROR):
                return None
            return val.keyBits.sym
        elif isinstance(val, (TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT)) and field == "mode":
            if val.algorithm in (TPM2_ALG.XOR, TPM2_ALG.NULL, TPM2_ALG.ERROR):
                return None
            return val.mode.sym
        elif isinstance(val, TPMT_KEYEDHASH_SCHEME):
            if val.scheme == TPM2_ALG.HMAC:
                return val.details.hmac
            if val.scheme == TPM2_ALG.XOR:
                return val.details.exclusiveOr
            if val.scheme == TPM2_ALG.NULL:
                return None
        elif isinstance(val, TPMT_SIG_SCHEME):
            if val.scheme == TPM2_ALG.ECDAA:
                return val.details.ecdaa
            return val.details.any
        elif isinstance(val, TPMT_KDF_SCHEME):
            if val.scheme in (TPM2_ALG.NULL, TPM2_ALG.ERROR):
                return None
            return val.details.mgf1
        elif isinstance(
            val, (TPMT_ASYM_SCHEME, TPMT_RSA_SCHEME, TPMT_RSA_DECRYPT, TPMT_ECC_SCHEME)
        ):
            if val.scheme == TPM2_ALG.ECDAA:
                return val.details.ecdaa
            if val.scheme in (TPM2_ALG.RSAES, TPM2_ALG.NULL, TPM2_ALG.ERROR):
                return None
            return val.details.anySig
        elif isinstance(val, TPMT_SIGNATURE):
            if val.sigAlg in (TPM2_ALG.RSASSA, TPM2_ALG.RSAPSS):
                return val.signature.rsassa
            if val.sigAlg in (
                TPM2_ALG.ECDSA,
                TPM2_ALG.ECDAA,
                TPM2_ALG.SM2,
                TPM2_ALG.ECSCHNORR,
            ):
                return val.signature.ecdsa
            if val.sigAlg == TPM2_ALG.HMAC:
                return val.signature.hmac
        elif (
            isinstance(val, (TPMT_PUBLIC_PARMS, TPMT_PUBLIC)) and field == "parameters"
        ):
            if val.type == TPM2_ALG.KEYEDHASH:
                return val.parameters.keyedHashDetail
            if val.type == TPM2_ALG.SYMCIPHER:
                return val.parameters.symDetail
            if val.type == TPM2_ALG.RSA:
                return val.parameters.rsaDetail
            if val.type == TPM2_ALG.ECC:
                return val.parameters.eccDetail
        elif isinstance(val, TPMT_PUBLIC) and field == "unique":
            if val.type in (TPM2_ALG.KEYEDHASH, TPM2_ALG.SYMCIPHER):
                return val.unique.keyedHash
            if val.type == TPM2_ALG.RSA:
                return val.unique.rsa
            if val.type == TPM2_ALG.ECC:
                return val.unique.ecc
        elif isinstance(val, TPMT_SENSITIVE):
            return val.sensitive.any
        elif isinstance(val, TPMT_HA):
            return bytes(val)
        raise ValueError(
            f"unable to find union selector for field {field} in {val.__class__.__name__}"
        )

    def encode(
        self,
        val: Union[
            TPMA_FRIENDLY_INTLIST,
            TPM_FRIENDLY_INT,
            int,
            TPM2B_SIMPLE_OBJECT,
            TPML_OBJECT,
            TPM_OBJECT,
            bytes,
        ],
    ) -> Union[int, str, Dict[str, Any], list, None]:
        """Encode a TPM type

        Args:
            val (Union[TPMA_FRIENDLY_INTLIST, TPM_FRIENDLY_INT, int, TPM2B_SIMPLE_OBJECT, TPML_OBJECT, TPM_OBJECT, bytes]): The value to encode

        Returns:
            Union[int, str, dict. list, None] depending on input value.

        Raises:
            TypeError: if val is either a TPM union or if type of val is unsupported.
        """
        if isinstance(val, TPM_OBJECT) and self._is_union(val):
            raise TypeError(f"tried to encode union {val.__class__.__name__}")
        if isinstance(val, TPMA_FRIENDLY_INTLIST):
            return self.encode_friendly_intlist(val)
        elif isinstance(val, TPM_FRIENDLY_INT):
            return self.encode_friendly_int(val)
        elif isinstance(val, int):
            return self.encode_int(val)
        elif isinstance(val, TPM2B_SIMPLE_OBJECT):
            return self.encode_simple_tpm2b(val)
        elif isinstance(
            val,
            (
                TPM2B_PUBLIC,
                TPM2B_SENSITIVE_CREATE,
                TPM2B_ECC_POINT,
                TPM2B_SENSITIVE,
                TPM2B_NV_PUBLIC,
                TPM2B_CREATION_DATA,
            ),
        ):
            return self.encode_complex_tpm2b(val)
        elif isinstance(val, TPML_OBJECT):
            return self.encode_tpml(val)
        elif isinstance(val, TPM_OBJECT):
            return self.encode_struct(val)
        elif isinstance(val, bytes):
            if len(val) == 0:
                return None
            return hexlify(val).decode("ascii")
        raise TypeError(f"unable to encode value of type {val.__class__.__name__}")

    def encode_int(self, val: int) -> int:
        """Encode an integer value

        Args:
            val (int): The value to encode

        Returns:
            The value as an int
        """
        return val

    def encode_friendly_int(self, val: TPM_FRIENDLY_INT) -> int:
        """Encode a TPM_FRIENDLY_INT value

        Args:
            val (TPM_FRIENDLY_INT): The value to encode

        Returns:
            The value as an int
        """
        return int(val)

    def encode_friendly_intlist(self, val: TPMA_FRIENDLY_INTLIST) -> int:
        """Encode a TPMA_FRIENDLY_INTLIST value

        Args:
            val (TPMA_FRIENDLY_INTLIST): The value to encode

        Returns:
            The value as an int
        """
        return int(val)

    def encode_simple_tpm2b(self, val: TPM2B_SIMPLE_OBJECT) -> Union[str, None]:
        """Encode a TPM2B_SIMPLE_OBJECT value

        Args:
            val (TPM2B_SIMPLE_OBJECT): The value to encode

        Returns:
            The value buffer as hex encoded string, or None if empty
        """
        if len(val) == 0:
            return None
        return str(val)

    def encode_complex_tpm2b(
        self,
        val: Union[
            TPM2B_PUBLIC,
            TPM2B_SENSITIVE_CREATE,
            TPM2B_ECC_POINT,
            TPM2B_SENSITIVE,
            TPM2B_NV_PUBLIC,
            TPM2B_CREATION_DATA,
        ],
    ) -> Dict[str, Any]:
        """Encode a complex TPM2B object value

        Args:
            val (Union[TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPM2B_ECC_POINT, TPM2B_SENSITIVE, TPM2B_NV_PUBLIC, TPM2B_CREATION_DATA]): The value to encode

        Returns:
            The non-size field encoded as a dict
        """
        val = self._get_complex_field(val)
        return self.encode_struct(val)

    def encode_tpml(self, val: TPML_OBJECT) -> list:
        """Encode a TPML_OBJECT value

        Args:
            val (TPML_OBJECT): The value to encode

        Returns:
            A list with all the elements encoded
        """
        l = list()
        for v in val:
            ev = self.encode(v)
            l.append(ev)
        return l

    def encode_pcrselect(self, val: bytes) -> List[int]:
        """Encode a pcrSelect value

        Args:
            val (bytes): The value to encode

        Returns:
            A list containing all the set PCRs
        """
        pcrs = []
        val = reversed(bytes(val))
        si = int.from_bytes(val, "big")
        for i in range(0, si.bit_length()):
            b = si >> i
            if 1 & b:
                pcrs.append(i)

        return pcrs

    def encode_struct(self, val: TPM_OBJECT) -> Dict[str, Any]:
        """Encode a TPM_OBJECT value

        Args:
            val (TPM_OBJECT): The value to encode

        Returns:
            A dict containing all the encoded fields
        """
        d = dict()
        attrs = dir(val._cdata)
        for a in attrs:
            av = getattr(val, a)
            if self._is_union(av):
                av = self._get_by_selector(val, a)
                if av is None:
                    continue
            if a == "pcrSelect" and "sizeofSelect" in attrs:
                sv = self.encode_pcrselect(av[0 : val.sizeofSelect])
            elif a == "sizeofSelect":
                continue
            else:
                sv = self.encode(av)
            if sv is not None:
                d[a] = sv
        if len(d) == 0:
            return None
        return d

    def decode(
        self,
        dst: Union[
            TPMA_FRIENDLY_INTLIST,
            TPM_FRIENDLY_INT,
            int,
            TPM2B_SIMPLE_OBJECT,
            TPML_OBJECT,
            TPM_OBJECT,
        ],
        src: Union[int, str, dict, list],
    ) -> Union[
        TPMA_FRIENDLY_INTLIST,
        TPM_FRIENDLY_INT,
        int,
        TPM2B_SIMPLE_OBJECT,
        TPML_OBJECT,
        TPM_OBJECT,
    ]:
        """Decode a value into a TPM type

        Args:
            dst (Union[TPMA_FRIENDLY_INTLIST, TPM_FRIENDLY_INT, int, TPM2B_SIMPLE_OBJECT, TPML_OBJECT, TPM_OBJECT]): The (type) instance to decode into
            src (Union[int, str, dict, list]): The value to decode

        Returns:
            The decoded value as a Union[TPMA_FRIENDLY_INTLIST, TPM_FRIENDLY_INT, int, TPM2B_SIMPLE_OBJECT, TPML_OBJECT, TPM_OBJECT]

        Raises:
            TypeError: if dst is not a supported type or dst is a TPM union
        """
        if isinstance(dst, TPM_OBJECT) and self._is_union(dst):
            raise TypeError(f"tried to decode union {dst.__class__.__name__}")
        if isinstance(dst, TPMA_FRIENDLY_INTLIST):
            return self.decode_friendly_intlist(dst, src)
        elif isinstance(dst, TPM_FRIENDLY_INT):
            return self.decode_friendly_int(dst, src)
        elif isinstance(dst, int):
            return self.decode_int(dst, src)
        elif isinstance(dst, TPM2B_SIMPLE_OBJECT):
            return self.decode_simple_tpm2b(dst, src)
        elif isinstance(
            dst,
            (
                TPM2B_PUBLIC,
                TPM2B_SENSITIVE_CREATE,
                TPM2B_ECC_POINT,
                TPM2B_SENSITIVE,
                TPM2B_NV_PUBLIC,
                TPM2B_CREATION_DATA,
            ),
        ):
            return self.decode_complex_tpm2b(dst, src)
        elif isinstance(dst, TPML_OBJECT):
            return self.decode_tpml(dst, src)
        elif isinstance(dst, TPM_OBJECT):
            return self.decode_struct(dst, src)
        raise TypeError(f"unable to decode value of type {dst.__class__.__name__}")

    def decode_int(self, dst: int, src: int) -> int:
        """Decode an integer value

        Args:
            dst (int): the instance type to encode the integer as
            src (int): the int value to decode

        Returns:
            The int value as them same type as dst
        """
        return type(dst)(src)

    def decode_friendly_int(self, dst: TPM_FRIENDLY_INT, src: int) -> TPM_FRIENDLY_INT:
        """Decode a TPM_FRIENDLY_INT value

        Args:
            dst (TPM_FRIENDLY_INT): the instance type to encode the integer as
            src (int): the int value to decode

        Returns:
            The int value as them same type as dst
        """
        return type(dst)(src)

    def decode_friendly_intlist(
        self, dst: TPMA_FRIENDLY_INTLIST, src: int
    ) -> TPMA_FRIENDLY_INTLIST:
        """Decode a TPMA_FRIENDLY_INTLIST value

        Args:
            dst (TPMA_FRIENDLY_INTLIST): the instance type to encode the integer as
            src (int): the int value to decode

        Returns:
            The int value as them same type as dst
        """
        return type(dst)(src)

    def decode_simple_tpm2b(
        self, dst: TPM2B_SIMPLE_OBJECT, src: str
    ) -> TPM2B_SIMPLE_OBJECT:
        """Decode a TPM2B_SIMPLE_OBJECT value

        Args:
            dst (TPM2B_SIMPLE_OBJECT): the instance to decode into
            src (str): the value as a hex encoded string

        Returns:
            dst containing the decoded value
        """
        dst.buffer = unhexlify(src)
        return dst

    def decode_complex_tpm2b(
        self,
        dst: Union[
            TPM2B_PUBLIC,
            TPM2B_SENSITIVE_CREATE,
            TPM2B_ECC_POINT,
            TPM2B_SENSITIVE,
            TPM2B_NV_PUBLIC,
            TPM2B_CREATION_DATA,
        ],
        src: Dict[str, Any],
    ) -> Union[
        TPM2B_PUBLIC,
        TPM2B_SENSITIVE_CREATE,
        TPM2B_ECC_POINT,
        TPM2B_SENSITIVE,
        TPM2B_NV_PUBLIC,
        TPM2B_CREATION_DATA,
    ]:
        """Decode a complex TPM2V value

        Args:
            dst (Union[TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPM2B_ECC_POINT, TPM2B_SENSITIVE, TPM2B_NV_PUBLIC, TPM2B_CREATION_DATA]): The instance to decode into
            src (dict): The value to decode

        Returns:
            dst containing the decoded value
        """
        f = self._get_complex_field(dst)
        f = self.decode(f, src)
        self._set_complex_field(dst, f)
        return dst

    def decode_tpml(self, dst: TPML_OBJECT, src: list) -> TPML_OBJECT:
        """Decode a TPML_OBJECT value

        Args:
            dst (TPML_OBJECT): The TPML_OBJECT to decode into
            src (list): the list of values to decode

        Returns:
            dst containing the decoded elements
        """
        ec = self._get_element_type(dst)
        i = 0
        for v in src:
            e = ec()
            e = self.decode(e, v)
            dst[i] = e
            i = i + 1
        return dst

    def decode_pcrselect(self, dst: bytes, src: List[int]) -> bytes:
        """Decode a pctSelect value

        Args:
            dst (bytes): the pcrSelect value, currently ignored
            src (List[int]): a list of the selected PCRs

        Returns:
            bytes with the selected PCR bits set
        """
        pcrs = 0
        for pcr in src:
            pcrs = pcrs | (1 << pcr)
        return bytes(reversed(pcrs.to_bytes(4, "big"))).rstrip(b"\x00")

    def decode_struct(self, dst: TPM_OBJECT, src: Dict[str, Any]) -> TPM_OBJECT:
        """Decode a TPM_OBJECT value

        Args:
            dst (TPM_OBJECT): The TPM_OBJECT instance to decode into
            src (dict): A dict of fields/values to decode

        Returns:
            dst containing the decoded values

        Raises:
            ValueError if strict is True and src containings unknown fields
        """
        if self._case_insensitive:
            fm = [(x.lower(), x) for x in dir(dst._cdata)]
            fields = dict(fm)
            km = [(x.lower(), x) for x in src.keys()]
            keys = dict(km)
        else:
            fm = [(x, x) for x in dir(dst._cdata)]
            fields = dict(fm)
            km = [(x, x) for x in src.keys()]
            keys = dict(km)
        mkeys = [x for x in keys if x in fields]
        if self._strict:
            missing = [x for x in keys if x not in fields]
            if len(missing) > 0:
                raise ValueError(f"unknown field(s) {', '.join(missing)} in source")
        for k in mkeys:
            rk = keys[k]
            rf = fields[k]
            df = getattr(dst, rf)
            if self._is_union(df):
                df = self._get_by_selector(dst, rf)
                rdst = df
            else:
                rdst = dst
            sf = src[rk]
            if rf == "pcrSelect" and "sizeofSelect" in fields.values():
                dv = self.decode_pcrselect(df, sf)
                setattr(rdst, "sizeofSelect", len(dv))
            elif rf == "sizeofSelect" and "pcrSelect" in fields.values():
                continue
            else:
                dv = self.decode(df, sf)
            setattr(rdst, rk, dv)
        return dst


class json_encdec(base_encdec):
    """Encode TPM types according to TCG TSS 2.0 JSON Data Types and Policy Language Specification

    Args:
        strict (bool): If a exception should be raised for unknown fields during decoding, defaults to True.
        case_insensitive (bool): If field names should be case insensitive during decoding, defaults to True.
    """

    def __init__(self, strict=True, case_insensitive=True):
        super().__init__(strict=strict, case_insensitive=case_insensitive)

    def encode_int(self, val: int) -> Union[List[int], int]:
        """Encode an int value

        Args:
            val (int): The value to encode

        Returns:
            An int or a list of two ints if size is over 54 bit
        """
        if val >= 0x100000000:
            return [(val >> 32) & 0xFFFFFFFF, val & 0xFFFFFFFF]
        return int(val)

    def encode_friendly_int(self, val: TPM_FRIENDLY_INT) -> Union[str, int, List[int]]:
        """Encode a TPM_FRIENDLY_INT value

        Args:
            val (TPM_FRIENDLY_INT): The value to encode

        Returns:
            A str if the val matches a constant, otherwise an encoded int
        """
        if isinstance(val, TPM_FRIENDLY_INT) and type(val).contains(val):
            return str(val)
        return self.encode_int(val)

    def encode_friendly_intlist(self, val: TPMA_FRIENDLY_INTLIST) -> Dict[str, int]:
        """Encode a TPMA_FRIENDLY_INTLIST valut

        Args:
            val (TPMA_FRIENDLY_INT): The value to encode

        Returns
            A dict with the attribute names as the key and 1 as the value
        """
        attrs = dict()
        for i in range(0, 32):
            c = val & (1 << i)
            if type(val).contains(c) and c != 0:
                k = str(c)
                attrs[k] = 1
        if isinstance(val, TPMA_NV) and val.nt:
            attrs["nt"] = self.encode_friendly_int(val.nt)
        if isinstance(val, TPMA_CC) and val.commandindex:
            attrs["commandindex"] = val.commandindex
        if isinstance(val, TPMA_CC) and val.chandles:
            attrs["chandles"] = val.chandles
        if isinstance(val, TPMA_LOCALITY) and val > 31:
            attrs["extended"] = (
                val & TPMA_LOCALITY.EXTENDED_MASK
            ) >> TPMA_LOCALITY.EXTENDED_SHIFT

        return attrs

    def decode_int(self, dst: int, src: Union[int, str, List[int]]) -> int:
        """Decode an int value

        Args:
            dst (int): The int instance, currently ignored
            src (Union[int, str, List[int]]): An int, a string containing the hex encoded value or a list of two ints

        Returns:
            A decoded int
        """
        if isinstance(src, str):
            dst = int(src, base=0)
        elif isinstance(src, list):
            dst = src[0] << 32 | src[1]
        else:
            dst = int(src)
        return dst

    def decode_friendly_int(
        self, dst: TPM_FRIENDLY_INT, src: Union[int, str]
    ) -> TPM_FRIENDLY_INT:
        """Decode a TPM_FRIENDLY_INT

        Args:
            dst (TPM_FRIENDLY_INT): The instance which type will be used
            src (Union[str, int]): Either a string containing the name of a constant or an int

        Returns:
            An instance of the same type as dst containing the decoded value
        """
        p = dst.__class__.__name__.lower() + "_"
        if isinstance(src, str):
            src = src.lower()
            if src.startswith(p):
                src = src[len(p)]
        try:
            return type(dst).parse(src)
        except (TypeError, ValueError):
            pass
        v = self.decode_int(dst, src)
        return type(dst)(v)

    def decode_friendly_intlist(
        self, dst: TPMA_FRIENDLY_INTLIST, src: Union[Dict[str, Any], List[str]]
    ) -> TPMA_FRIENDLY_INTLIST:
        """Decode a TPMA_FRIENDLY_INTLIST value

        Args:
            dst (TPMA_FRIENDLY_INTLIST): The instance which type will be used
            src (Union[Dict[str, Any], List[str]]): Either a dict with the attribute name as the key or a list of attributes

        Returns:
            An instance of the same type as dst containing the decoded value

        """
        attrs = type(dst)()
        p = dst.__class__.__name__.lower() + "_"
        if isinstance(src, dict):
            for k, v in src.items():
                k = k.lower()
                if k.startswith(p):
                    k = k[len(p) :]
                if isinstance(dst, TPMA_NV) and k == "nt":
                    nt = self.decode_friendly_int(TPM2_NT(), v)
                    attrs = attrs | nt << TPMA_NV.TPM2_NT_SHIFT
                    continue
                elif isinstance(dst, TPMA_CC) and k == "commandindex":
                    commandindex = self.decode_int(int(), v)
                    attrs = attrs | commandindex
                    continue
                elif isinstance(dst, TPMA_CC) and k == "chandles":
                    chandles = self.decode_int(int(), v)
                    attrs = attrs | chandles << TPMA_CC.CHANDLES_SHIFT
                    continue
                elif isinstance(dst, TPMA_LOCALITY) and k == "extended":
                    extended = self.decode_int(int(), v)
                    attrs = attrs | extended << TPMA_LOCALITY.EXTENDED_SHIFT
                    continue
                a = type(dst).parse(k)
                if (isinstance(v, str) and v.lower() in ("clear", "no")) or not v:
                    attrs = attrs & ~a
                else:
                    attrs = attrs | a
        elif isinstance(src, list):
            for v in src:
                v = v.lower()
                if v.startswith(p):
                    v = v[len(p) :]
                a = type(dst).parse(v)
                attrs = attrs | a
        else:
            attrs = self.decode_int(dst, src)

        return attrs

    def decode_simple_tpm2b(self, dst, src):
        """Decode a TPM2B_SIMPLE_OBJECT value

        Args:
            dst (TPM2B_SIMPLE_OBJECT): The object to store the decoded value in
            src (Union[str, List[int]]): Either a hex encoded string or a list of integers

        Returns:
            dst containing the decoded value
        """
        if isinstance(src, list):
            dst.buffer = bytes(src)
            return dst
        if src[0:2] == "0x":
            src = src[2:]
        dst.buffer = unhexlify(src)
        return dst


class tools_encdec(base_encdec):
    """Encode TPM types in the same format as tpm2-tools
    """

    def encode_friendly_int_nv(self, val: TPM_FRIENDLY_INT) -> Dict[str, str]:
        d = {
            "friendly": str(val),
            "value": int(val),
        }
        if isinstance(val, TPM2_ALG) and d["friendly"] == "sha":
            d["friendly"] = "sha1"
        return d

    def encode_friendly_intlist_nv(self, val: TPMA_FRIENDLY_INTLIST) -> Dict[str, str]:
        return {
            "friendly": str(val),
            "value": int(val),
        }

    def encode_friendly_int(self, val: TPM_FRIENDLY_INT) -> Dict[str, Any]:
        d = {
            "value": str(val),
            "raw": int(val),
        }
        if isinstance(val, TPM2_ALG) and d["value"] == "sha":
            d["value"] = "sha1"
        elif isinstance(val, TPM2_ALG) and d["value"] == "null":
            d["value"] = None
        return d

    def encode_tpma_cc(self, val: TPMA_CC) -> Dict[str, Any]:
        cc = val & TPMA_CC.COMMANDINDEX_MASK
        ccname = None
        for attr in dir(TPM2_CC):
            if getattr(TPM2_CC, attr) == cc:
                ccname = f"TPM2_CC_{attr}"
                break
        if ccname is None:
            ccname = f"{cc:#x}"
        d = dict()
        d["value"] = int(val)
        d["commandIndex"] = int(cc)
        reserved1 = (val & TPMA_CC.RESERVED1_MASK) >> 16
        d["reserved1"] = int(reserved1)
        d["nv"] = 1 if val & TPMA_CC.NV else 0
        d["extensive"] = 1 if val & TPMA_CC.EXTENSIVE else 0
        d["flushed"] = 1 if val & TPMA_CC.FLUSHED else 0
        chandles = (val & TPMA_CC.CHANDLES_MASK) >> TPMA_CC.CHANDLES_SHIFT
        d["cHandles"] = int(chandles)
        d["rHandle"] = 1 if val & TPMA_CC.RHANDLE else 0
        d["V"] = 1 if val & TPMA_CC.V else 0
        res = (val & TPMA_CC.RES_MASK) >> TPMA_CC.RES_SHIFT
        d["Res"] = int(res)
        return {ccname: d}

    def encode_tpma_permanent(self, val: TPMA_PERMANENT) -> Dict[str, int]:
        d = dict()
        d["ownerAuthSet"] = 1 if val & TPMA_PERMANENT.OWNERAUTHSET else 0
        d["endorsementAuthSet"] = 1 if val & TPMA_PERMANENT.ENDORSEMENTAUTHSET else 0
        d["lockoutAuthSet"] = 1 if val & TPMA_PERMANENT.LOCKOUTAUTHSET else 0
        d["reserved1"] = 1 if val & TPMA_PERMANENT.RESERVED1_MASK else 0
        d["disableClear"] = 1 if val & TPMA_PERMANENT.DISABLECLEAR else 0
        d["inLockout"] = 1 if val & TPMA_PERMANENT.INLOCKOUT else 0
        d["tpmGeneratedEPS"] = 1 if val & TPMA_PERMANENT.TPMGENERATEDEPS else 0
        d["reserved2"] = 1 if val & TPMA_PERMANENT.RESERVED2_MASK else 0
        return d

    def encode_tpma_startup_clear(self, val: TPMA_STARTUP) -> Dict[str, int]:
        d = dict()
        d["phEnable"] = 1 if val & TPMA_STARTUP.CLEAR_PHENABLE else 0
        d["shEnable"] = 1 if val & TPMA_STARTUP.CLEAR_SHENABLE else 0
        d["ehEnable"] = 1 if val & TPMA_STARTUP.CLEAR_EHENABLE else 0
        d["phEnableNV"] = 1 if val & TPMA_STARTUP.CLEAR_PHENABLENV else 0
        d["reserved1"] = 1 if val & TPMA_STARTUP.CLEAR_RESERVED1_MASK else 0
        d["orderly"] = 1 if val & TPMA_STARTUP.CLEAR_ORDERLY else 0
        return d

    def encode_tpma_session(self, val: TPMA_SESSION) -> Dict[str, str]:
        attrs = str(val)
        return {"Session-Attributes": attrs}

    def encode_friendly_intlist(self, val: TPMA_FRIENDLY_INTLIST) -> Dict[str, Any]:
        if isinstance(val, TPMA_CC):
            return self.encode_tpma_cc(val)
        elif isinstance(val, TPMA_PERMANENT):
            return self.encode_tpma_permanent(val)
        elif isinstance(val, TPMA_STARTUP):
            return self.encode_tpma_startup_clear(val)
        elif isinstance(val, TPMA_SESSION):
            return self.encode_tpma_session(val)
        return {
            "value": str(val),
            "raw": int(val),
        }

    def encode_tpms_nv_public(self, val: TPMS_NV_PUBLIC) -> Dict[str, Any]:
        d = dict()
        d["name"] = hexlify(val.get_name().name).decode("ascii")
        d["hash algorithm"] = self.encode_friendly_int_nv(val.nameAlg)
        d["attributes"] = self.encode_friendly_intlist_nv(val.attributes)
        d["size"] = self.encode_int(val.dataSize)
        if val.authPolicy.size:
            d["authorization policy"] = self.encode(val.authPolicy).upper()
        return {int(val.nvIndex): d}

    def encode_tpmt_sym_def(
        self, val: Union[TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT]
    ) -> Dict[str, Any]:
        d = dict()
        d["sym-alg"] = self.encode(val.algorithm)
        d["sym-mode"] = self.encode(val.mode.sym)
        d["sym-keybits"] = self.encode(val.keyBits.sym)
        return d

    def encode_tpmt_public(self, val: TPMT_PUBLIC) -> Dict[str, Any]:
        d = dict()
        params = self._get_by_selector(val, "parameters")
        unique = self._get_by_selector(val, "unique")
        keydata = None
        d["name-alg"] = self.encode(val.nameAlg)
        d["attributes"] = self.encode(val.objectAttributes)
        d["type"] = self.encode(val.type)
        if val.type == TPM2_ALG.SYMCIPHER:
            sd = self.encode(params.sym)
            d.update(sd)
            keydata = self.encode(unique)
        elif val.type == TPM2_ALG.KEYEDHASH:
            details = self._get_by_selector(params.scheme, "scheme")
            d["hash-alg"] = self.encode(details.hashAlg)
            if params.scheme == TPM2_ALG.XOR:
                d["kdfa-alg"] = self.encode(details.kdf)
        elif val.type == TPM2_ALG.RSA:
            e = 65537 if not params.exponent else params.exponent
            d["exponent"] = self.encode(e)
            d["bits"] = self.encode(params.keyBits)
            d["scheme"] = self.encode(params.scheme.scheme)
            if params.scheme.scheme != TPM2_ALG.RSAES:
                d["scheme-halg"] = self.encode(params.scheme.details.anySig.hashAlg)
            sd = self.encode(params.symmetric)
            d.update(sd)
            keydata = self.encode(unique)
        elif val.type == TPM2_ALG.ECC:
            d["curve-id"] = self.encode(params.curveID)
            d["kdfa-alg"] = self.encode(params.kdf.scheme)
            d["kdfa-halg"] = self.encode(params.kdf.details.mgf1.hashAlg)
            d["scheme"] = self.encode(params.scheme.scheme)
            d["scheme-halg"] = self.encode(params.scheme.details.anySig.hashAlg)
            if params.scheme.scheme == TPM2_ALG.ECDAA:
                d["scheme-count"] = self.encode(params.scheme.details.ecdaa.count)
            sd = self.encode(params.symmetric)
            d.update(sd)
            keydata = {
                "x": self.encode(unique.x),
                "y": self.encode(unique.y),
            }
        if keydata and val.type == TPM2_ALG.ECC:
            d.update(keydata)
        elif keydata:
            d[str(val.type)] = keydata
        if val.authPolicy.size:
            d["authorization policy"] = self.encode(val.authPolicy)
        return d

    def encode_tpms_alg_property(self, val: TPMS_ALG_PROPERTY) -> Dict[str, Any]:
        d = dict()
        d["value"] = int(val.alg)
        d["asymmetric"] = 1 if val.algProperties & TPMA_ALGORITHM.ASYMMETRIC else 0
        d["symmetric"] = 1 if val.algProperties & TPMA_ALGORITHM.SYMMETRIC else 0
        d["hash"] = 1 if val.algProperties & TPMA_ALGORITHM.HASH else 0
        d["object"] = 1 if val.algProperties & TPMA_ALGORITHM.OBJECT else 0
        reserved = (val.algProperties & TPMA_ALGORITHM.RESERVED1_MASK) >> 4
        d["reserved"] = int(reserved)
        d["signing"] = 1 if val.algProperties & TPMA_ALGORITHM.SIGNING else 0
        d["encrypting"] = 1 if val.algProperties & TPMA_ALGORITHM.ENCRYPTING else 0
        d["method"] = 1 if val.algProperties & TPMA_ALGORITHM.METHOD else 0
        algname = str(val.alg)
        return {algname: d}

    def encode_tpms_pcr_selection(self, val: TPMS_PCR_SELECTION) -> Dict[str, List]:
        pcrsel = list()
        pb = reversed(bytes(val.pcrSelect[0 : val.sizeofSelect]))
        pi = int.from_bytes(pb, "big")
        algname = str(val.hash)
        if algname == "sha":
            algname = "sha1"
        i = 0
        for i in range(0, val.sizeofSelect * 8):
            if (1 << i) & pi:
                pcrsel.append(i)
        return {algname: pcrsel}

    def _build_pt_map(self) -> Dict[int, str]:
        pmap = dict()
        for attr in dir(TPM2_PT):
            pa = getattr(TPM2_PT, attr)
            if not isinstance(pa, int) or attr in ("GROUP", "FIXED", "VAR"):
                continue
            pan = f"TPM2_PT_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_VENDOR):
            pa = getattr(TPM2_PT_VENDOR, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_VENDOR_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_FIRMWARE):
            pa = getattr(TPM2_PT_FIRMWARE, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_FIRMWARE_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_HR):
            pa = getattr(TPM2_PT_HR, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_HR_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_NV):
            pa = getattr(TPM2_PT_NV, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_NV_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_CONTEXT):
            pa = getattr(TPM2_PT_CONTEXT, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_CONTEXT_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_PS):
            pa = getattr(TPM2_PT_PS, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_PS_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_AUDIT):
            pa = getattr(TPM2_PT_AUDIT, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_AUDIT_{attr}"
            pmap[pa] = pan
        for attr in dir(TPM2_PT_PCR):
            pa = getattr(TPM2_PT_PCR, attr)
            if not isinstance(pa, int):
                continue
            pan = f"TPM2_PT_PCR_{attr}"
            pmap[pa] = pan

        return pmap

    def encode_tpms_tagged_property(self, val: TPMS_TAGGED_PROPERTY) -> Dict[str, Any]:
        p = val.property
        pmap = self._build_pt_map()
        pname = pmap.get(p, None)
        if pname is None:
            raise ValueError(f"Unsupported property {p}")
        d = dict()
        if p == TPM2_PT.LEVEL:
            d["raw"] = val.value
        elif p & TPM2_PT.FIXED:
            d["raw"] = val.value
        if p == TPM2_PT.REVISION:
            v = val.value / 100
            d["value"] = v
        elif p in (
            TPM2_PT.FAMILY_INDICATOR,
            TPM2_PT.MANUFACTURER,
            TPM2_PT_VENDOR.STRING_1,
            TPM2_PT_VENDOR.STRING_2,
            TPM2_PT_VENDOR.STRING_3,
            TPM2_PT_VENDOR.STRING_4,
        ):
            b = val.value.to_bytes(4, "big")
            d["value"] = b.rstrip(b"\x00").decode("ascii")
        elif p == TPM2_PT.MODES:
            if val.value & TPMA_MODES.FIPS_140_2:
                d["value"] = "TPMA_MODES_FIPS_140_2"
            elif val.value & TPMA_MODES.RESERVED1_MASK:
                d["value"] = "TPMA_MODES_RESERVED1 (these bits shouldn't be set)"
        elif p == TPM2_PT.PERMANENT:
            d = self.encode(TPMA_PERMANENT(val.value))
        elif p == TPM2_PT.STARTUP_CLEAR:
            d = self.encode(TPMA_STARTUP(val.value))
        elif p & TPM2_PT.VAR:
            d = val.value
        return {pname: d}

    def encode_tpms_clock_info(self, val: TPMS_CLOCK_INFO) -> Dict[str, int]:
        d = dict()
        d["clock"] = val.clock
        d["resetCount"] = val.resetCount
        d["restartCount"] = val.restartCount
        d["safe"] = val.safe
        return d

    def encode_tpms_context(self, val: TPMS_CONTEXT) -> Dict[str, Any]:
        d = dict()
        d["version"] = 1
        if val.hierarchy in (TPM2_RH.OWNER, TPM2_RH.PLATFORM, TPM2_RH.ENDORSEMENT):
            d["hierarchy"] = str(val.hierarchy)
        else:
            d["hierarchy"] = "null"
        d["handle"] = f"0x{val.savedHandle:X} ({val.savedHandle:d})"
        d["sequence"] = val.sequence
        d["contextBlob"] = {"size": val.contextBlob.size}
        return d

    def encode_tpms_nv_pin_counter_parameters(
        self, val: TPMS_NV_PIN_COUNTER_PARAMETERS
    ) -> Dict[str, int]:
        d = dict()
        d["pinCount"] = val.pinCount
        d["pinLimit"] = val.pinLimit
        return d

    def encode_tpml_tagged_tpm_property(
        self, val: TPML_TAGGED_TPM_PROPERTY
    ) -> Dict[str, Any]:
        d = dict()
        for tp in val:
            ep = self.encode(tp)
            d.update(ep)
        return d

    def encode_tpml_pcr_selection(self, val: TPML_PCR_SELECTION) -> Dict[str, List]:
        sels = list()
        for sel in val:
            es = self.encode(sel)
            sels.append(es)
        return {"selected-pcrs": sels}

    def encode_tpml_ecc_curve(self, val: TPML_ECC_CURVE) -> Dict[str, str]:
        d = dict()
        emap = dict()
        for attr in dir(TPM2_ECC):
            ev = getattr(TPM2_ECC, attr)
            if not isinstance(ev, int):
                continue
            en = f"TPM2_ECC_{attr}"
            emap[ev] = en
        for e in val:
            ename = emap[e]
            d[ename] = int(e)
        return d

    def encode_tpml_handle(self, val: TPML_HANDLE) -> List[int]:
        handles = list()
        for h in val:
            hs = int(h)
            handles.append(hs)
        return handles

    def encode_tpml_alg_property(self, val: TPML_ALG_PROPERTY) -> Dict[str, Dict]:
        d = dict()
        for v in val:
            ev = self.encode(v)
            d.update(ev)
        return d

    def encode_tpml_cca(self, val: TPML_CCA) -> Dict[str, Dict]:
        d = dict()
        for v in val:
            ev = self.encode(v)
            d.update(ev)
        return d

    def encode_tpml_digest_values(self, val: TPML_DIGEST_VALUES) -> Dict[str, str]:
        d = dict()
        for v in val:
            an = str(v.hashAlg)
            if an == "sha":
                an = "sha1"
            d[an] = hexlify(bytes(v)).decode("ascii")
        return d

    def encode_tpml_alg(self, val: TPML_ALG) -> Dict[str, str]:
        algs = list()
        for v in val:
            an = str(v)
            if an == "sha":
                an = "sha1"
            algs.append(an)
        return {"remaining": " ".join(algs)}

    def encode_tpml(
        self,
        val: Union[
            TPML_PCR_SELECTION,
            TPML_TAGGED_TPM_PROPERTY,
            TPML_ECC_CURVE,
            TPML_HANDLE,
            TPML_ALG_PROPERTY,
            TPML_CCA,
            TPML_DIGEST_VALUES,
            TPML_ALG,
        ],
    ) -> Any:
        t = type(val)
        if isinstance(val, TPML_PCR_SELECTION):
            return self.encode_tpml_pcr_selection(val)
        elif isinstance(val, TPML_TAGGED_TPM_PROPERTY):
            return self.encode_tpml_tagged_tpm_property(val)
        elif isinstance(val, TPML_ECC_CURVE):
            return self.encode_tpml_ecc_curve(val)
        elif isinstance(val, TPML_HANDLE):
            return self.encode_tpml_handle(val)
        elif isinstance(val, TPML_ALG_PROPERTY):
            return self.encode_tpml_alg_property(val)
        elif isinstance(val, TPML_CCA):
            return self.encode_tpml_cca(val)
        elif isinstance(val, TPML_DIGEST_VALUES):
            return self.encode_tpml_digest_values(val)
        elif isinstance(val, TPML_ALG):
            return self.encode_tpml_alg(val)
        raise ValueError(f"unsupported list {t.__name__}")

    def encode_struct(
        self,
        val: Union[
            TPMS_NV_PUBLIC,
            TPMT_PUBLIC,
            TPMT_SYM_DEF,
            TPMT_SYM_DEF_OBJECT,
            TPMS_ALG_PROPERTY,
            TPMS_PCR_SELECTION,
            TPMS_TAGGED_PROPERTY,
            TPMS_CLOCK_INFO,
            TPMS_CONTEXT,
        ],
    ) -> Dict[str, Any]:
        t = type(val)
        if isinstance(val, TPMS_NV_PUBLIC):
            return self.encode_tpms_nv_public(val)
        elif isinstance(val, TPMT_PUBLIC):
            return self.encode_tpmt_public(val)
        elif isinstance(val, (TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT)):
            return self.encode_tpmt_sym_def(val)
        elif isinstance(val, TPMS_ALG_PROPERTY):
            return self.encode_tpms_alg_property(val)
        elif isinstance(val, TPMS_PCR_SELECTION):
            return self.encode_tpms_pcr_selection(val)
        elif isinstance(val, TPMS_TAGGED_PROPERTY):
            return self.encode_tpms_tagged_property(val)
        elif isinstance(val, TPMS_CLOCK_INFO):
            return self.encode_tpms_clock_info(val)
        elif isinstance(val, TPMS_CONTEXT):
            return self.encode_tpms_context(val)
        elif isinstance(val, TPMS_NV_PIN_COUNTER_PARAMETERS):
            return self.encode_tpms_nv_pin_counter_parameters(val)
        raise ValueError(f"unsupported structure {t.__name__}")

    def decode_int(self, dst: int, src: Union[Dict[str, Any], int]) -> int:
        if isinstance(src, dict) and "counter" in src:
            return src.get("counter")
        elif isinstance(src, dict) and "bits" in src:
            v = 0
            for i in src["bits"]:
                v = v | (1 << i)
            return v
        return super().decode_int(dst, src)

    def decode_friendly_int(
        self, dst: TPM_FRIENDLY_INT, src: Dict[str, Union[int, str]]
    ) -> TPM_FRIENDLY_INT:
        if "friendly" in src and "value" in src:
            raw = src.get("value")
        else:
            raw = src.get("raw")
        return dst.__class__(raw)

    def decode_tpma_cc(self, src: Dict[str, Dict]) -> TPMA_CC:
        _, v = src.popitem()
        val = v.get("value")
        return TPMA_CC(val)

    def decode_tpma_permanent(self, src: Dict[str, int]) -> TPMA_PERMANENT:
        rv = TPMA_PERMANENT()
        if src.get("ownerAuthSet"):
            rv = rv | TPMA_PERMANENT.OWNERAUTHSET
        if src.get("endorsementAuthSet"):
            rv = rv | TPMA_PERMANENT.ENDORSEMENTAUTHSET
        if src.get("lockoutAuthSet"):
            rv = rv | TPMA_PERMANENT.LOCKOUTAUTHSET
        if src.get("disableClear"):
            rv = rv | TPMA_PERMANENT.DISABLECLEAR
        if src.get("inLockout"):
            rv = rv | TPMA_PERMANENT.INLOCKOUT
        if src.get("tpmGeneratedEPS"):
            rv = rv | TPMA_PERMANENT.TPMGENERATEDEPS
        return rv

    def decode_tpma_startup(self, src: Dict[str, int]) -> TPMA_STARTUP:
        rv = TPMA_STARTUP()
        if src.get("phEnable"):
            rv |= TPMA_STARTUP.CLEAR_PHENABLE
        if src.get("shEnable"):
            rv |= TPMA_STARTUP.CLEAR_SHENABLE
        if src.get("ehEnable"):
            rv |= TPMA_STARTUP.CLEAR_EHENABLE
        if src.get("phEnableNV"):
            rv |= TPMA_STARTUP.CLEAR_PHENABLENV
        if src.get("orderly"):
            rv |= TPMA_STARTUP.CLEAR_ORDERLY
        return rv

    def decode_tpma_session(self, src: Dict[str, str]) -> TPMA_SESSION:
        astr = src.get("Session-Attributes")
        return TPMA_SESSION.parse(astr)

    def decode_friendly_intlist(
        self, dst: TPMA_FRIENDLY_INTLIST, src: Dict[str, Any]
    ) -> TPMA_FRIENDLY_INTLIST:
        if isinstance(dst, TPMA_CC):
            return self.decode_tpma_cc(src)
        elif isinstance(dst, TPMA_PERMANENT):
            return self.decode_tpma_permanent(src)
        elif isinstance(dst, TPMA_STARTUP):
            return self.decode_tpma_startup(src)
        elif isinstance(dst, TPMA_SESSION):
            return self.decode_tpma_session(src)
        if "friendly" in src and "value" in src:
            raw = src.get("value")
        else:
            raw = src.get("raw")
        return dst.__class__(raw)

    def decode_tpml_pcr_selection(
        self, dst: TPML_PCR_SELECTION, src: Dict[str, List]
    ) -> TPML_PCR_SELECTION:
        l = src.get("selected-pcrs")
        i = 0
        for e in l:
            s = self.decode(TPMS_PCR_SELECTION(), e)
            dst[i] = s
            i += 1
        return dst

    def decode_tpml_tagged_tpm_property(
        self, dst: TPML_TAGGED_TPM_PROPERTY, src: Dict[str, Any]
    ) -> TPML_TAGGED_TPM_PROPERTY:
        i = 0
        for k, v in src.items():
            tp = TPMS_TAGGED_PROPERTY()
            self.decode(tp, {k: v})
            dst[i] = tp
            i += 1
        return dst

    def decode_tpml_ecc_curve(
        self, dst: TPML_ECC_CURVE, src: Dict[str, int]
    ) -> TPML_ECC_CURVE:
        i = 0
        for k, v in src.items():
            dst[i] = TPM2_ECC(v)
            i += 1
        return dst

    def decode_tpml_handle(self, dst: TPML_HANDLE, src: List[int]) -> TPML_HANDLE:
        i = 0
        for h in src:
            dst[i] = TPM2_HANDLE(h)
            i += 1
        return dst

    def decode_tpml_alg_property(
        self, dst: TPML_ALG_PROPERTY, src: Dict[str, Dict]
    ) -> TPML_ALG_PROPERTY:
        i = 0
        for k, v in src.items():
            dst[i] = self.decode(TPMS_ALG_PROPERTY(), {k: v})
            i += 1
        return dst

    def decode_tpml_cca(self, dst: TPML_CCA, src: Dict[str, Dict]) -> TPML_CCA:
        i = 0
        for k, v in src.items():
            dst[i] = self.decode(TPMA_CC(), {k: v})
            i += 1
        return dst

    def decode_tpml_digest_values(
        self, dst: TPML_DIGEST_VALUES, src: Dict[str, str]
    ) -> TPML_DIGEST_VALUES:
        digs = list()
        for an, dh in src.items():
            alg = TPM2_ALG.parse(an)
            dig = unhexlify(dh)
            digs.append(TPMT_HA(hashAlg=alg, digest=TPMU_HA(sha512=dig)))
        return TPML_DIGEST_VALUES(digs)

    def decode_tpml_alg(self, dst: TPML_ALG, src: Dict[str, str]) -> TPML_ALG:
        algstr = src.get("remaining", "")
        algs = algstr.split()
        return TPML_ALG([TPM2_ALG.parse(x) for x in algs])

    def decode_tpml(
        self,
        dst: Union[
            TPML_PCR_SELECTION,
            TPML_TAGGED_TPM_PROPERTY,
            TPML_ECC_CURVE,
            TPML_HANDLE,
            TPML_ALG_PROPERTY,
            TPML_CCA,
            TPML_DIGEST_VALUES,
            TPML_ALG,
        ],
        src: Union[Dict, List],
    ) -> Union[
        TPML_PCR_SELECTION,
        TPML_TAGGED_TPM_PROPERTY,
        TPML_ECC_CURVE,
        TPML_HANDLE,
        TPML_ALG_PROPERTY,
        TPML_CCA,
        TPML_DIGEST_VALUES,
        TPML_ALG,
    ]:
        t = type(dst)
        if isinstance(dst, TPML_PCR_SELECTION):
            return self.decode_tpml_pcr_selection(dst, src)
        elif isinstance(dst, TPML_TAGGED_TPM_PROPERTY):
            return self.decode_tpml_tagged_tpm_property(dst, src)
        elif isinstance(dst, TPML_ECC_CURVE):
            return self.decode_tpml_ecc_curve(dst, src)
        elif isinstance(dst, TPML_HANDLE):
            return self.decode_tpml_handle(dst, src)
        elif isinstance(dst, TPML_ALG_PROPERTY):
            return self.decode_tpml_alg_property(dst, src)
        elif isinstance(dst, TPML_CCA):
            return self.decode_tpml_cca(dst, src)
        elif isinstance(dst, TPML_DIGEST_VALUES):
            return self.decode_tpml_digest_values(dst, src)
        elif isinstance(dst, TPML_ALG):
            return self.decode_tpml_alg(dst, src)
        raise ValueError(f"unsupported list {t.__name__}")

    def decode_tpms_nv_public(
        self, dst: TPMS_NV_PUBLIC, src: Dict[str, Dict]
    ) -> TPMS_NV_PUBLIC:
        k, v = src.popitem()
        dst.nvIndex = k
        dst.nameAlg = self.decode(TPM2_ALG(), v.get("hash algorithm"))
        dst.attributes = self.decode(TPMA_NV(), v.get("attributes"))
        dst.dataSize = v["size"]
        dst.authPolicy = self.decode(TPM2B_DIGEST(), v.get("authorization policy", b""))
        return dst

    def decode_tpmt_public(self, dst: TPMT_PUBLIC, src: Dict) -> TPMT_PUBLIC:
        dst.nameAlg = self.decode(TPM2_ALG(), src["name-alg"])
        dst.objectAttributes = self.decode(TPMA_OBJECT(), src["attributes"])
        dst.type = self.decode(TPM2_ALG(), src["type"])
        if dst.type == TPM2_ALG.RSA:
            e = src["exponent"]
            dst.parameters.rsaDetail.exponent = 0 if e == 65537 else e
            dst.parameters.rsaDetail.keyBits = src["bits"]
            dst.parameters.rsaDetail.scheme.scheme = self.decode(
                TPM2_ALG(), src["scheme"]
            )
            if dst.parameters.rsaDetail.scheme.scheme != TPM2_ALG.RSAES:
                dst.parameters.rsaDetail.scheme.details.anySig.hashAlg = self.decode(
                    TPM2_ALG(), src["scheme-halg"]
                )
            dst.parameters.rsaDetail.symmetric = self.decode(TPMT_SYM_DEF_OBJECT(), src)
            dst.unique.rsa = unhexlify(src["rsa"])
        elif dst.type == TPM2_ALG.ECC:
            dst.parameters.eccDetail.curveID = self.decode(TPM2_ECC(), src["curve-id"])
            dst.parameters.eccDetail.kdf.scheme = self.decode(
                TPM2_ALG(), src["kdfa-alg"]
            )
            dst.parameters.eccDetail.kdf.details.mgf1.hashAlg = self.decode(
                TPM2_ALG(), src["kdfa-halg"]
            )
            dst.parameters.eccDetail.scheme.scheme = self.decode(
                TPM2_ALG(), src["scheme"]
            )
            dst.parameters.eccDetail.scheme.details.anySig.hashAlg = self.decode(
                TPM2_ALG(), src["scheme-halg"]
            )
            if dst.parameters.eccDetail.scheme.scheme == TPM2_ALG.ECDAA:
                dst.parameters.eccDetail.scheme.details.ecdaa.count
            dst.parameters.eccDetail.symmetric = self.decode(TPMT_SYM_DEF_OBJECT(), src)
            dst.unique.ecc.x = unhexlify(src["x"])
            dst.unique.ecc.y = unhexlify(src["y"])
        elif dst.type == TPM2_ALG.KEYEDHASH:
            dst.parameters.keyedHashDetail.scheme.scheme = self.decode(
                TPM2_ALG(), src["algorithm"]
            )
            dst.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = self.decode(
                TPM2_ALG(), src["hash-alg"]
            )
            if dst.parameters.keyedHashDetail.scheme.scheme == TPM2_ALG.XOR:
                dst.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = self.decode(
                    TPM2_ALG(), src["kdfa-alg"]
                )
            dst.unique.keyedHash = unhexlify(src["keyedhash"])
        elif dst.type == TPM2_ALG.SYMCIPHER:
            dst.parameters.symDetail.sym = self.decode(TPMT_SYM_DEF_OBJECT(), src)
            dst.unique.sym = unhexlify(src["symcipher"])
        return dst

    def decode_tpmt_sym_def(
        self, dst: Union[TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT], src: Dict[str, Any]
    ) -> Union[TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT]:
        dst.algorithm = self.decode(TPM2_ALG(), src["sym-alg"])
        dst.mode.sym = self.decode(TPM2_ALG(), src["sym-mode"])
        dst.keyBits.sym = src["sym-keybits"]
        return dst

    def decode_tpms_alg_property(
        self, dst: TPMS_ALG_PROPERTY, src: Dict[str, Dict]
    ) -> TPMS_ALG_PROPERTY:
        _, d = src.popitem()
        dst.alg = TPM2_ALG(d["value"])
        if d.get("asymmetric"):
            dst.algProperties |= TPMA_ALGORITHM.ASYMMETRIC
        if d.get("symmetric"):
            dst.algProperties |= TPMA_ALGORITHM.SYMMETRIC
        if d.get("hash"):
            dst.algProperties |= TPMA_ALGORITHM.HASH
        if d.get("object"):
            dst.algProperties |= TPMA_ALGORITHM.OBJECT
        if d.get("reserved"):
            res = d["reserved"] << 4
            dst.algProperties |= TPMA_ALGORITHM.RESERVED1_MASK & res
        if d.get("signing"):
            dst.algProperties |= TPMA_ALGORITHM.SIGNING
        if d.get("encrypting"):
            dst.algProperties |= TPMA_ALGORITHM.ENCRYPTING
        if d.get("method"):
            dst.algProperties |= TPMA_ALGORITHM.METHOD

        return dst

    def decode_tpms_pcr_selection(
        self, dst: TPMS_PCR_SELECTION, src: Dict[str, Dict]
    ) -> TPMS_PCR_SELECTION:
        k, v = src.popitem()
        dst.hash = TPM2_ALG.parse(k)
        pi = 0
        for p in v:
            pi |= 1 << p
        pb = bytes(reversed(pi.to_bytes(4, "big"))).rstrip(b"\x00")
        dst.sizeofSelect = len(pb)
        dst.pcrSelect = pb
        return dst

    def decode_tpms_tagged_property(
        self, dst: TPMS_TAGGED_PROPERTY, src: Dict[str, Any]
    ) -> TPMS_TAGGED_PROPERTY:
        pmap = dict([(v, k) for k, v in self._build_pt_map().items()])
        ps, v = src.popitem()
        dst.property = pmap[ps]
        if dst.property == TPM2_PT.PERMANENT:
            dst.value = self.decode(TPMA_PERMANENT(), v)
        elif dst.property == TPM2_PT.STARTUP_CLEAR:
            dst.value = self.decode(TPMA_STARTUP(), v)
        elif isinstance(v, int):
            dst.value = v
        elif isinstance(v, dict):
            dst.value = v.get("raw")

    def decode_tpms_clock_info(
        self, dst: TPMS_CLOCK_INFO, src: Dict[str, int]
    ) -> TPMS_CLOCK_INFO:
        dst.clock = src["clock"]
        dst.resetCount = src["resetCount"]
        dst.restartCount = src["restartCount"]
        dst.safe = src["safe"]
        return dst

    def decode_struct(
        self,
        dst: Union[
            TPMS_NV_PUBLIC,
            TPMT_PUBLIC,
            TPMT_SYM_DEF,
            TPMT_SYM_DEF_OBJECT,
            TPMS_ALG_PROPERTY,
            TPMS_PCR_SELECTION,
            TPMS_TAGGED_PROPERTY,
            TPMS_CLOCK_INFO,
        ],
        src: Dict[str, Any],
    ) -> Union[
        TPMS_NV_PUBLIC,
        TPMT_PUBLIC,
        TPMT_SYM_DEF,
        TPMT_SYM_DEF_OBJECT,
        TPMS_ALG_PROPERTY,
        TPMS_PCR_SELECTION,
        TPMS_TAGGED_PROPERTY,
        TPMS_CLOCK_INFO,
    ]:
        t = type(dst)
        if isinstance(dst, TPMS_NV_PUBLIC):
            return self.decode_tpms_nv_public(dst, src)
        elif isinstance(dst, TPMT_PUBLIC):
            return self.decode_tpmt_public(dst, src)
        elif isinstance(dst, (TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT)):
            return self.decode_tpmt_sym_def(dst, src)
        elif isinstance(dst, TPMS_ALG_PROPERTY):
            return self.decode_tpms_alg_property(dst, src)
        elif isinstance(dst, TPMS_PCR_SELECTION):
            return self.decode_tpms_pcr_selection(dst, src)
        elif isinstance(dst, TPMS_TAGGED_PROPERTY):
            return self.decode_tpms_tagged_property(dst, src)
        elif isinstance(dst, TPMS_CLOCK_INFO):
            return self.decode_tpms_clock_info(dst, src)
        raise ValueError(f"unsupported structure {t.__name__}")

    def _is_pcr_tuple(self, val):
        return (
            isinstance(val, tuple)
            and len(val) == 2
            and isinstance(val[0], TPML_PCR_SELECTION)
            and isinstance(val[1], TPML_DIGEST)
        )

    def _is_pcr_tuples(self, val):
        if not val or not isinstance(val, collections.abc.Iterable):
            return False
        for v in val:
            if not self._is_pcr_tuple(v):
                return False
        return True

    def encode_pcr_tuple(
        self, val: Tuple[TPML_PCR_SELECTION, TPML_DIGEST]
    ) -> Dict[str, List]:
        d = dict()
        sels, digs = val
        di = 0
        for s in sels:
            bn = str(s.hash)
            if bn == "sha":
                bn = "sha1"
            if d.get(bn) is None:
                d[bn] = dict()
            rb = bytes(reversed(bytes(s.pcrSelect)))
            pi = int.from_bytes(rb, "big")
            for i in range(0, s.sizeofSelect * 8):
                if 1 << i & pi:
                    d[bn][i] = int.from_bytes(digs[di], "big")
                    di += 1
        return d

    def encode_pcr_tuples(
        self, val: List[Tuple[TPML_PCR_SELECTION, TPML_DIGEST]]
    ) -> Dict[str, List]:
        d = dict()
        for v in val:
            pv = self.encode(v)
            for bank, digs in pv.items():
                if d.get(bank) is None:
                    d[bank] = dict()
                d[bank].update(digs)
        return d

    def encode_name(self, val: TPM2B_NAME) -> Dict[str, str]:
        return {"name": hexlify(val.name).decode("ascii")}

    def encode(self, val):
        if self._is_pcr_tuple(val):
            return self.encode_pcr_tuple(val)
        elif self._is_pcr_tuples(val):
            return self.encode_pcr_tuples(val)
        elif isinstance(val, TPM2B_NAME):
            return self.encode_name(val)
        return super().encode(val)

    def decode_pcr_tuples(
        self,
        dst: Tuple[TPML_PCR_SELECTION, TPML_DIGEST],
        src: Dict[str, Dict[int, str]],
    ) -> List[Tuple[TPML_PCR_SELECTION, TPML_DIGEST]]:
        pcrdigs = list()
        for bank, pcrs in src.items():
            bankalg = TPM2_ALG.parse(bank)
            digsize = _get_digest_size(bankalg)
            for pcr, di in pcrs.items():
                dig = di.to_bytes(digsize, "big")
                pcrdigs.append((bankalg, pcr, dig))
        rl = list()
        sels = list()
        digs = list()
        sel = TPMS_PCR_SELECTION(hash=pcrdigs[0][0])
        for bank, pcr, dig in pcrdigs:
            if bank != sel.hash:
                sels.append(sel)
                sel = TPMS_PCR_SELECTION(hash=bank)
            sel.pcrSelect[pcr // 8] |= 1 << (pcr % 8)
            sel.sizeofSelect = len(bytes(sel.pcrSelect).rstrip(b"\x00"))
            digs.append(dig)
            if len(digs) == 8:
                sels.append(sel)
                sel = TPMS_PCR_SELECTION(hash=bank)
                sl = TPML_PCR_SELECTION(sels)
                dl = TPML_DIGEST(digs)
                rl.append((sl, dl))
                sels = list()
                digs = list()
        if len(digs):
            sels.append(sel)
            sl = TPML_PCR_SELECTION(sels)
            dl = TPML_DIGEST(digs)
            rl.append((sl, dl))
        return rl

    def decode_name(self, dst: TPM2B_NAME, src: Dict[str, str]) -> TPM2B_NAME:
        if "loaded-key" in src:
            src = src["loaded-key"]
        name = unhexlify(src["name"])
        name2b = TPM2B_NAME(name=name)
        return name2b

    def decode_tpmt_ha(self, dst: TPMT_HA, src: Dict[str, str]) -> TPMT_HA:
        k, v = src.popitem()
        alg = TPM2_ALG.parse(k)
        ds = _get_digest_size(alg)
        dig = v.to_bytes(ds, "big")
        dst.hashAlg = alg
        dst.digest.sha512 = dig
        return dst

    def decode_tpms_nv_pin_counter_parameters(
        self, dst: TPMS_NV_PIN_COUNTER_PARAMETERS, src: Dict[str, Union[Dict, int]]
    ) -> TPMS_NV_PIN_COUNTER_PARAMETERS:
        print(src)
        if "pinfail" in src:
            src = src["pinfail"]
        elif "pinpass" in src:
            src = src["pinpass"]
        dst.pinCount = src["pinCount"]
        dst.pinLimit = src["pinLimit"]
        return dst

    def decode(self, dst, src):
        if self._is_pcr_tuple(dst):
            return self.decode_pcr_tuples(dst, src)
        elif isinstance(dst, TPM2B_NAME):
            return self.decode_name(dst, src)
        elif isinstance(dst, TPMT_HA):
            return self.decode_tpmt_ha(dst, src)
        elif isinstance(dst, TPMS_NV_PIN_COUNTER_PARAMETERS):
            return self.decode_tpms_nv_pin_counter_parameters(dst, src)
        return super().decode(dst, src)


def to_yaml(val: TPM_OBJECT) -> str:
    enc = tools_encdec()
    ev = enc.encode(val)
    return yaml.safe_dump(ev, sort_keys=False)


def from_yaml(src, dst):
    dec = tools_encdec()
    d = yaml.safe_load(src)
    return dec.decode(dst, d)
