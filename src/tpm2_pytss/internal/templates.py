# SPDX-License-Identifier: BSD-2

from ..types import (
    TPMT_SYM_DEF_OBJECT,
    TPMU_SYM_KEY_BITS,
    TPMU_SYM_MODE,
    TPM2B_PUBLIC,
    TPMT_PUBLIC,
    TPMU_PUBLIC_PARMS,
    TPMS_RSA_PARMS,
    TPMT_RSA_SCHEME,
    TPMU_PUBLIC_ID,
    TPMS_ECC_PARMS,
    TPMT_ECC_SCHEME,
    TPMT_KDF_SCHEME,
    TPMS_ECC_POINT,
    TPM2_HANDLE,
)
from ..constants import (
    TPM2_ALG,
    TPMA_OBJECT,
    TPM2_ECC,
)
from typing import ClassVar, Optional, Sequence


class template_attributes:
    low = (
        TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN
        | TPMA_OBJECT.ADMINWITHPOLICY
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
    )
    high = (
        TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN
        | TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.ADMINWITHPOLICY
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
    )


class template_policy:
    low = b"\x83q\x97gD\x84\xb3\xf8\x1a\x90\xcc\x8dF\xa5\xd7$\xfdR\xd7n\x06R\x0bd\xf2\xa1\xda\x1b3\x14i\xaa"
    sha256 = b"\xca=\n\x99\xa2\xb99\x06\xf7\xa34$\x14\xef\xcf\xb3\xa3\x85\xd4L\xd1\xfdE\x90\x89\xd1\x9bPq\xc0\xb7\xa0"
    sha384 = b"\xb2n}(\xd1\x1aP\xbcS\xd8\x82\xbc\xf5\xfd:\x1a\x07AH\xbb5\xd3\xb4\xe4\xcb\x1c\n\xd9\xbd\xe4\x19\xca\xcbG\xba\ti\x96F\x15\x0f\x9f\xc0\x00\xf3\xf8\x0e\x12"
    sha512 = b'\xb8"\x1c\xa6\x9e\x85P\xa4\x91M\xe3\xfa\xa6\xa1\x8c\x07,\xc0\x12\x08\x07:\x92\x8d]f\xd5\x9e\xf7\x9eI\xa4)\xc4\x1ak&\x95q\xd5~\xdb%\xfb\xdb\x188BV\x08\xb4\x13\xcdaj_m\xb5\xb6\x07\x1a\xf9\x9b\xea'
    sm3_256 = b"\x16x`\xa3_,\\5g\xf9\xc9'\xacV\xc02\xf3\xb3\xa6F/\x8d\x03y\x98\xe7\xa1\x0fw\xfaEJ"


class template_symmetric:
    low = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(aes=128),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    aes256 = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(aes=256),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    sm4 = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.SM4,
        keyBits=TPMU_SYM_KEY_BITS(sm4=128),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )


class ek_template:
    cert_index: ClassVar[TPM2_HANDLE]
    nonce_index: ClassVar[Optional[TPM2_HANDLE]] = None
    template: ClassVar[TPM2B_PUBLIC]
    _templates: ClassVar[dict[str, type["ek_template"]]] = dict()
    _names: ClassVar[Sequence[str]]

    def __init_subclass__(cls):
        for name in cls._names:
            name = name.lower()
            ek_template._templates[name] = cls

    @classmethod
    def lookup(cls, name: str) -> "ek_template":
        name = name.lower()
        template = cls._templates.get(name, None)
        return template

    @classmethod
    def available_templates(cls) -> list[str]:
        return cls._templates.keys()


class ek_rsa2048(ek_template):
    _names = ("EK-RSA2048", "L-1")
    cert_index = TPM2_HANDLE(0x01C00002)
    nonce_index = cert_index + 1
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=template_attributes.low,
            authPolicy=template_policy.low,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=template_symmetric.low,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=2048,
                ),
            ),
            unique=TPMU_PUBLIC_ID(rsa=b"\x00" * 256),
        )
    )


class ek_ecc256(ek_template):
    _names = ("EK-ECC256", "L-2")
    cert_index = TPM2_HANDLE(0x01C0000A)
    nonce_index = cert_index + 1
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=template_attributes.low,
            authPolicy=template_policy.low,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=template_symmetric.low,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                )
            ),
            unique=TPMU_PUBLIC_ID(ecc=TPMS_ECC_POINT(x=b"\x00" * 32, y=b"\x00" * 32)),
        )
    )


class ek_high_rsa2048(ek_template):
    _names = ("EK-HIGH-RSA2048", "H-1")
    cert_index = TPM2_HANDLE(0x01C00012)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha256,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=template_symmetric.low,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=2048,
                ),
            ),
        )
    )


class ek_high_ecc256(ek_template):
    _names = ("EK-HIGH-ECC256", "H-2")
    cert_index = TPM2_HANDLE(0x01C00014)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha256,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=template_symmetric.low,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )


class ek_high_ecc384(ek_template):
    _names = ("EK-HIGH-ECC384", "H-3")
    cert_index = TPM2_HANDLE(0x01C00016)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha384,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=template_symmetric.aes256,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P384,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )


class ek_high_ecc521(ek_template):
    _names = ("EK-HIGH-ECC521", "H-4")
    cert_index = TPM2_HANDLE(0x01C00018)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA512,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha512,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=template_symmetric.aes256,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P521,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )


class ek_high_ecc_sm2_p256(ek_template):
    _names = ("EK-HIGH-ECCSM2P256", "H-5")
    cert_index = TPM2_HANDLE(0x01C0001A)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SM3_256,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sm3_256,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=template_symmetric.sm4,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.SM2_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )


class ek_high_rsa3072(ek_template):
    _names = ("EK-HIGH-RSA3072", "H-6")
    cert_index = TPM2_HANDLE(0x01C0001C)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha384,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=template_symmetric.aes256,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=3072,
                ),
            ),
        )
    )


class ek_high_rsa4096(ek_template):
    _names = ("EK-HIGH-RSA4096", "H-7")
    cert_index = TPM2_HANDLE(0x01C0001E)
    template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=template_attributes.high,
            authPolicy=template_policy.sha384,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=template_symmetric.aes256,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=4096,
                ),
            ),
        )
    )
