# SPDX-License-Identifier: BSD-2

import warnings
import base64
from ._libtpm2_pytss import lib
from .types import *
from .constants import TPM2_ECC, TPM2_CAP, ESYS_TR
from cryptography.hazmat import asn1
from cryptography.x509 import ObjectIdentifier
from typing import Annotated

_parent_rsa_template = TPMT_PUBLIC(
    type=TPM2_ALG.RSA,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        rsaDetail=TPMS_RSA_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
            keyBits=2048,
            exponent=0,
        ),
    ),
)

_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            curveID=TPM2_ECC.NIST_P256,
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)

_rsa_template = TPMT_PUBLIC(
    type=TPM2_ALG.RSA,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.SIGN_ENCRYPT
    | TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        rsaDetail=TPMS_RSA_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
            scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)

_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.SIGN_ENCRYPT
    | TPMA_OBJECT.NODA
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN,
    authPolicy=b"",
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
        ),
    ),
)

_loadablekey_oid = ObjectIdentifier("2.23.133.10.1.3")

_pem_begin = b"-----BEGIN TSS2 PRIVATE KEY-----\n"
_pem_end = b"-----END TSS2 PRIVATE KEY-----\n"


def _tssprivkey_pem_unarmor(data: bytes) -> bytes:
    begin = data.find(_pem_begin)
    if begin == -1:
        raise ValueError("beginning of PEM not found")
    skip = begin + len(_pem_begin)
    end = data.find(_pem_end, skip)
    if end == -1:
        raise ValueError("end of PEM not found")
    pem_data = data[skip:end]
    der_data = base64.b64decode(pem_data)
    return der_data


def _tssprivkey_pem_armor(data: bytes) -> bytes:
    # base64 encode
    pem_data = base64.b64encode(data)
    # split with max length
    split_data = _pem_begin
    index = 0
    while len(pem_data[index:]):
        split_data += pem_data[index : index + 64] + b"\n"
        index += 64
    split_data += _pem_end
    # append beginning, split data, end
    return split_data


class TSSPrivKey(object):
    """TSSPrivKey is class to create/load keys for/from tpm2-tss-engine / tpm2-openssl.

    Note:
        Most users should use create_rsa/create_ecc together with to_pem and from_pem together with load.
    """

    @asn1.sequence
    class _tssprivkey_load:
        object_type: ObjectIdentifier = _loadablekey_oid
        empty_auth: asn1.TLV
        parent: int
        public: bytes
        private: bytes

    @asn1.sequence
    class _tssprivkey_save:
        object_type: ObjectIdentifier = _loadablekey_oid
        empty_auth: Annotated[bool, asn1.Explicit(0)]
        parent: int
        public: bytes
        private: bytes

    def __init__(self, private, public, empty_auth=True, parent=lib.TPM2_RH_OWNER):
        """Initialize TSSPrivKey using raw values.

        Args:
            private (TPM2B_PRIVATE): The private part of the TPM key.
            public (TPM2B_PUBLIC): The public part of the TPM key.
            empty_auth (bool): Defines if the authorization is a empty password, default is True.
            parent (int): The parent of the key, either a persistent key handle or TPM2_RH_OWNER, default is TPM2_RH_OWNER.
        """
        self._private = private
        self._public = public
        self._empty_auth = bool(empty_auth)
        self._parent = parent

    @property
    def private(self):
        """TPM2B_PRIVATE: The private part of the TPM key."""
        return self._private

    @property
    def public(self):
        """TPM2B_PUBLIC: The public part of the TPM key."""
        return self._public

    @property
    def empty_auth(self):
        """bool: Defines if the authorization is a empty password."""
        return self._empty_auth

    @property
    def parent(self):
        """int: Handle of the parent key."""
        return self._parent

    def to_der(self):
        """Encode the TSSPrivKey as DER encoded ASN.1.

        Returns:
            Returns the DER encoding as bytes.
        """
        pub = self.public.marshal()
        priv = self.private.marshal()
        seq = self._tssprivkey_save(
            empty_auth=self.empty_auth,
            parent=self.parent,
            public=pub,
            private=priv,
        )
        return asn1.encode_der(seq)

    def to_pem(self):
        """Encode the TSSPrivKey as PEM encoded ASN.1.

        Returns:
            Returns the PEM encoding as bytes.
        """
        der = self.to_der()
        return _tssprivkey_pem_armor(der)

    @staticmethod
    def _getparenttemplate(ectx):
        more = True
        al = list()
        while more:
            more, data = ectx.get_capability(TPM2_CAP.ALGS, 0, lib.TPM2_MAX_CAP_ALGS)
            algs = data.data.algorithms
            for i in range(0, algs.count):
                al.append(algs.algProperties[i].alg)
        if TPM2_ALG.ECC in al:
            return _parent_ecc_template
        elif TPM2_ALG.RSA in al:
            return _parent_rsa_template
        return None

    @staticmethod
    def _getparent(ectx, keytype, parent):
        if parent == lib.TPM2_RH_OWNER:
            template = TSSPrivKey._getparenttemplate(ectx)
        else:
            return ectx.tr_from_tpmpublic(parent)
        if template is None:
            raise RuntimeError("Unable to find supported parent key type")
        inpub = TPM2B_PUBLIC(publicArea=template)
        phandle, _, _, _, _ = ectx.create_primary(
            primary_handle=ESYS_TR.RH_OWNER,
            in_sensitive=TPM2B_SENSITIVE_CREATE(),
            in_public=inpub,
            outside_info=TPM2B_DATA(),
            creation_pcr=TPML_PCR_SELECTION(),
            session1=ESYS_TR.PASSWORD,
        )
        return phandle

    def load(self, ectx, password=None):
        """Load the TSSPrivKey.

        Args:
            ectx (ESAPI): The ESAPI instance to use for loading the key.
            password (bytes): The password of the TPM key, default is None.

        Returns:
            An ESYS_TR handle.
        """
        if not password and not self.empty_auth:
            raise RuntimeError("no password specified but it is required")
        elif password and self.empty_auth:
            warnings.warn("password specified but empty_auth is true")
        phandle = self._getparent(ectx, self.public.publicArea.type, self.parent)
        with phandle as phandle:
            handle = ectx.load(phandle, self.private, self.public)
        ectx.tr_set_auth(handle, password)
        return handle

    @classmethod
    def create(cls, ectx, template, parent=lib.TPM2_RH_OWNER, password=None):
        """Create a TssPrivKey using a template.

        Note:
            Most users should use the create_rsa or create_ecc methods.

        Args:
            ectx (ESAPI): The ESAPI instance to use for creating the key.
            template (TPM2B_PUBLIC): The key template.
            parent (int): The parent of the key, default is TPM2_RH_OWNER.
            password (bytes): The password to set for the key, default is None.

        Returns:
            Returns a TSSPrivKey instance with the created key.
        """
        insens = TPM2B_SENSITIVE_CREATE()
        emptyauth = True
        if password:
            insens.sensitive.userAuth = password
            emptyauth = False
        phandle = cls._getparent(ectx, template.type, parent)
        with phandle as phandle:
            private, public, _, _, _ = ectx.create(
                parent_handle=phandle,
                in_sensitive=insens,
                in_public=TPM2B_PUBLIC(publicArea=template),
                outside_info=TPM2B_DATA(),
                creation_pcr=TPML_PCR_SELECTION(),
            )
        return cls(private, public, emptyauth, parent)

    @classmethod
    def create_rsa(
        cls, ectx, keyBits=2048, exponent=0, parent=lib.TPM2_RH_OWNER, password=None
    ):
        """Create a RSA TssPrivKey using a standard RSA key template.

        Args:
            ectx (ESAPI): The ESAPI instance to use for creating the key.
            keyBits (int): Size of the RSA key, default is 2048.
            exponent (int): The exponent to use for the RSA key, default is 0 (TPM default).
            parent (int): The parent of the key, default is TPM2_RH_OWNER.
            password (bytes): The password to set for the key, default is None.

        Returns:
            Returns a TSSPrivKey instance with the created RSA key.
        """
        template = _rsa_template
        template.parameters.rsaDetail.keyBits = keyBits
        template.parameters.rsaDetail.exponent = exponent
        return cls.create(ectx, template, parent, password)

    @classmethod
    def create_ecc(
        cls, ectx, curveID=TPM2_ECC.NIST_P256, parent=lib.TPM2_RH_OWNER, password=None
    ):
        """Create an ECC TssPrivKey using a standard ECC key template.

        Args:
            ectx (ESAPI): The ESAPI instance to use for creating the key.
            curveID (int): The ECC curve to be used, default is TPM2_ECC.NIST_P256.
            parent (int): The parent of the key, default is TPM2_RH_OWNER.
            password (bytes): The password to set for the key, default is None.

        Returns:
            Returns a TSSPrivKey instance with the created ECC key.
        """
        template = _ecc_template
        template.parameters.eccDetail.curveID = curveID
        return cls.create(ectx, template, parent, password)

    @staticmethod
    def _decode_bad_bool(tlv: asn1.TLV) -> bool:
        # Some versions of tpm2-tss-engine and tpm2-openssl encode TRUE as 1.
        # That is an invalid DER encoding, so handle that here.
        data = bytes(tlv.data)
        if len(data) != 3:
            raise ValueError(
                f"unexpected emptyAuth ASN.1 TLV length, expected 3, got {len(data)}"
            )
        tag, length, value = data
        if tag != 1:
            raise ValueError(f"unexpected emptyAuth ASN.1 tag, expected 1, got {tag}")
        elif length != 1:
            raise ValueError(
                f"unexpected emptyAuth ASN.1 value length, expected 1, got {length}"
            )
        return bool(value)

    @classmethod
    def from_der(cls, data):
        """Load a TSSPrivKey from DER ASN.1.

        Args:
            data (bytes): The DER encoded ASN.1.

        Returns:
            Returns a TSSPrivKey instance.
        """
        seq = asn1.decode_der(cls._tssprivkey_load, data)
        if seq.object_type != _loadablekey_oid:
            raise TypeError("unsupported key type")
        empty_auth = cls._decode_bad_bool(seq.empty_auth)
        parent = seq.parent
        public, _ = TPM2B_PUBLIC.unmarshal(seq.public)
        private, _ = TPM2B_PRIVATE.unmarshal(seq.private)
        return cls(private, public, empty_auth, parent)

    @classmethod
    def from_pem(cls, data):
        """Load a TSSPrivKey from PEM ASN.1.

        Args:
            data (bytes): The PEM encoded ASN.1.

        Returns:
            Returns a TSSPrivKey instance.
        """
        der = _tssprivkey_pem_unarmor(data)
        return cls.from_der(der)
        pem_type, _, der = pem.unarmor(data)
        if pem_type != "TSS2 PRIVATE KEY":
            raise TypeError("unsupported PEM type")
        return cls.from_der(der)
