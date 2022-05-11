# SPDX-License-Identifier: BSD-2

import warnings
from ._libtpm2_pytss import lib
from .types import *
from .constants import TPM2_ECC, TPM2_CAP, ESYS_TR
from asn1crypto.core import ObjectIdentifier, Sequence, Boolean, OctetString, Integer
from asn1crypto import pem


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

# _BooleanOne is used to encode True in the same way as tpm2-tss-engine
class _BooleanOne(Boolean):
    def set(self, value):
        self._native = bool(value)
        self.contents = b"\x00" if not value else b"\x01"
        self._header = None
        if self._trailer != b"":
            self._trailer = b""


class TSSPrivKey(object):
    """TSSPrivKey is class to create/load keys for/from tpm2-tss-engine / tpm2-openssl.

    Note:
        Most users should use create_rsa/create_ecc together with to_pem and from_pem together with load.
    """

    class _tssprivkey_der(Sequence):
        _fields = [
            ("type", ObjectIdentifier),
            ("empty_auth", _BooleanOne, {"explicit": 0, "optional": True}),
            ("parent", Integer),
            ("public", OctetString),
            ("private", OctetString),
        ]

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
        seq = self._tssprivkey_der()
        seq["type"] = _loadablekey_oid.native
        seq["empty_auth"] = self.empty_auth
        seq["parent"] = self.parent
        pub = self.public.marshal()
        seq["public"] = pub
        priv = self.private.marshal()
        seq["private"] = priv
        return seq.dump()

    def to_pem(self):
        """Encode the TSSPrivKey as PEM encoded ASN.1.

        Returns:
            Returns the PEM encoding as bytes.
        """
        der = self.to_der()
        return pem.armor("TSS2 PRIVATE KEY", der)

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

    @classmethod
    def from_der(cls, data):
        """Load a TSSPrivKey from DER ASN.1.

        Args:
            data (bytes): The DER encoded ASN.1.

        Returns:
            Returns a TSSPrivKey instance.
        """
        seq = cls._tssprivkey_der.load(data)
        if seq["type"].native != _loadablekey_oid.native:
            raise TypeError("unsupported key type")
        empty_auth = seq["empty_auth"].native
        parent = seq["parent"].native
        public, _ = TPM2B_PUBLIC.unmarshal(bytes(seq["public"]))
        private, _ = TPM2B_PRIVATE.unmarshal(bytes(seq["private"]))
        return cls(private, public, empty_auth, parent)

    @classmethod
    def from_pem(cls, data):
        """Load a TSSPrivKey from PEM ASN.1.

        Args:
            data (bytes): The PEM encoded ASN.1.

        Returns:
            Returns a TSSPrivKey instance.
        """
        pem_type, _, der = pem.unarmor(data)
        if pem_type != "TSS2 PRIVATE KEY":
            raise TypeError("unsupported PEM type")
        return cls.from_der(der)
