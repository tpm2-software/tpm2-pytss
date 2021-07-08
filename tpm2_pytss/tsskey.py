"""
SPDX-License-Identifier: BSD-3
"""

import warnings
from ._libtpm2_pytss import lib
from .types import *
from asn1crypto.core import ObjectIdentifier, Sequence, Boolean, OctetString, Integer
from asn1crypto import pem


parent_rsa_template = TPMT_PUBLIC(
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

parent_ecc_template = TPMT_PUBLIC(
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

rsa_template = TPMT_PUBLIC(
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

ecc_template = TPMT_PUBLIC(
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

loadablekey_oid = ObjectIdentifier("2.23.133.10.1.3")

# BooleanOne is used to encode True in the same way as tpm2-tss-engine
class BooleanOne(Boolean):
    def set(self, value):
        self._native = bool(value)
        self.contents = b"\x00" if not value else b"\x01"
        self._header = None
        if self._trailer != b"":
            self._trailer = b""


class TSSPrivKey(object):
    class _tssprivkey_der(Sequence):
        _fields = [
            ("type", ObjectIdentifier),
            ("emptyAuth", BooleanOne, {"explicit": 0, "optional": True}),
            ("parent", Integer),
            ("public", OctetString),
            ("private", OctetString),
        ]

    def __init__(self, private, public, emptyAuth=True, parent=lib.TPM2_RH_OWNER):
        self._private = private
        self._public = public
        self._emptyAuth = bool(emptyAuth)
        self._parent = parent

    @property
    def private(self):
        return self._private

    @property
    def public(self):
        return self._public

    @property
    def emptyAuth(self):
        return self._emptyAuth

    @property
    def parent(self):
        return self._parent

    def toDER(self):
        seq = self._tssprivkey_der()
        seq["type"] = loadablekey_oid.native
        seq["emptyAuth"] = self.emptyAuth
        seq["parent"] = self.parent
        pub = self.public.marshal()
        seq["public"] = pub
        priv = self.private.marshal()
        seq["private"] = priv
        return seq.dump()

    def toPEM(self):
        der = self.toDER()
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
            return parent_ecc_template
        elif TPM2_ALG.RSA in al:
            return parent_rsa_template
        return None

    @staticmethod
    def _getparent(ectx, keytype, parent):
        if parent == lib.TPM2_RH_OWNER:
            template = TSSPrivKey._getparenttemplate(ectx)
        else:
            return ectx.tr_from_tpmpublic(parent)
        if template is None:
            raise RuntimeError("Unable to find supported parent key typ")
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
        if not password and not self.emptyAuth:
            raise RuntimeError("no password specified but it is required")
        elif password and self.emptyAuth:
            warnings.warn("password specified but emptyAuth is true")
        phandle = self._getparent(ectx, self.public.publicArea.type, self.parent)
        handle = ectx.load(phandle, self.private, self.public)
        ectx.set_auth(handle, password)
        return handle

    @classmethod
    def create(cls, ectx, template, parent=lib.TPM2_RH_OWNER, password=None):
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
        template = rsa_template
        template.parameters.rsaDetail.keyBits = keyBits
        template.parameters.rsaDetail.exponent = exponent
        return cls.create(ectx, template, parent, password)

    @classmethod
    def create_ecc(
        cls, ectx, curveID=TPM2_ECC.NIST_P256, parent=lib.TPM2_RH_OWNER, password=None
    ):
        template = ecc_template
        template.parameters.eccDetail.curveID = curveID
        return cls.create(ectx, template, parent, password)

    @classmethod
    def fromDER(cls, data):
        seq = cls._tssprivkey_der.load(data)
        if seq["type"].native != loadablekey_oid.native:
            raise TypeError("unsupported key type")
        emptyAuth = seq["emptyAuth"].native
        parent = seq["parent"].native
        public, _ = TPM2B_PUBLIC.unmarshal(bytes(seq["public"]))
        private, _ = TPM2B_PRIVATE.unmarshal(bytes(seq["private"]))
        return cls(private, public, emptyAuth, parent)

    @classmethod
    def fromPEM(cls, data):
        pem_type, _, der = pem.unarmor(data)
        if pem_type != "TSS2 PRIVATE KEY":
            raise TypeError("unsupported PEM type")
        return cls.fromDER(der)
