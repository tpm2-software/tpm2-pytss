from binascii import hexlify, unhexlify
from typing import Any, Union, List, Dict
from ._libtpm2_pytss import ffi
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
)


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
