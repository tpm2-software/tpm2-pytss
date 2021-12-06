from collections import namedtuple
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
)
from ..constants import (
    TPM2_ALG,
    TPMA_OBJECT,
    TPM2_ECC,
)


class _ek:
    _ek_tuple = namedtuple("_ek_tuple", ["cert_index", "ek_template"])
    _low_symmetric = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(aes=128),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    _low_attrs = (
        TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN
        | TPMA_OBJECT.ADMINWITHPOLICY
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
    )
    _low_policy = b"\x83q\x97gD\x84\xb3\xf8\x1a\x90\xcc\x8dF\xa5\xd7$\xfdR\xd7n\x06R\x0bd\xf2\xa1\xda\x1b3\x14i\xaa"
    _ek_rsa2048_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=_low_attrs,
            authPolicy=_low_policy,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=_low_symmetric,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=2048,
                ),
            ),
            unique=TPMU_PUBLIC_ID(rsa=b"\x00" * 256),
        )
    )
    _ek_ecc256_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=_low_attrs,
            authPolicy=_low_policy,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=_low_symmetric,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                )
            ),
            unique=TPMU_PUBLIC_ID(ecc=TPMS_ECC_POINT(x=b"\x00" * 32, y=b"\x00" * 32)),
        )
    )
    _high_attrs = (
        TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN
        | TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.ADMINWITHPOLICY
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
    )
    _256_symmetric = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(aes=256),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    _sm4_symmetric = TPMT_SYM_DEF_OBJECT(
        algorithm=TPM2_ALG.SM4,
        keyBits=TPMU_SYM_KEY_BITS(sm4=128),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    _sha256_policy = b"\xca=\n\x99\xa2\xb99\x06\xf7\xa34$\x14\xef\xcf\xb3\xa3\x85\xd4L\xd1\xfdE\x90\x89\xd1\x9bPq\xc0\xb7\xa0"
    _sha384_policy = b"\xb2n}(\xd1\x1aP\xbcS\xd8\x82\xbc\xf5\xfd:\x1a\x07AH\xbb5\xd3\xb4\xe4\xcb\x1c\n\xd9\xbd\xe4\x19\xca\xcbG\xba\ti\x96F\x15\x0f\x9f\xc0\x00\xf3\xf8\x0e\x12"
    _sha512_policy = b'\xb8"\x1c\xa6\x9e\x85P\xa4\x91M\xe3\xfa\xa6\xa1\x8c\x07,\xc0\x12\x08\x07:\x92\x8d]f\xd5\x9e\xf7\x9eI\xa4)\xc4\x1ak&\x95q\xd5~\xdb%\xfb\xdb\x188BV\x08\xb4\x13\xcdaj_m\xb5\xb6\x07\x1a\xf9\x9b\xea'
    _sm3_256_policy = b"\x16x`\xa3_,\\5g\xf9\xc9'\xacV\xc02\xf3\xb3\xa6F/\x8d\x03y\x98\xe7\xa1\x0fw\xfaEJ"
    _ek_high_rsa2048_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=_high_attrs,
            authPolicy=_sha256_policy,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=_low_symmetric,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=2048,
                ),
            ),
        )
    )
    _ek_high_ecc256_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=_high_attrs,
            authPolicy=_sha256_policy,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=_low_symmetric,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )
    _ek_high_ecc384_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=_high_attrs,
            authPolicy=_sha384_policy,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=_256_symmetric,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P384,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )
    _ek_high_ecc521_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA512,
            objectAttributes=_high_attrs,
            authPolicy=_sha512_policy,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=_256_symmetric,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.NIST_P521,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )
    _ek_high_eccsm2p521_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SM3_256,
            objectAttributes=_high_attrs,
            authPolicy=_sm3_256_policy,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=_sm4_symmetric,
                    scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                    curveID=TPM2_ECC.SM2_P256,
                    kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                ),
            ),
        ),
    )
    _ek_high_rsa3072_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=_high_attrs,
            authPolicy=_sha384_policy,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=_256_symmetric,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=3072,
                ),
            ),
        )
    )
    _ek_high_rsa4096_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.RSA,
            nameAlg=TPM2_ALG.SHA384,
            objectAttributes=_high_attrs,
            authPolicy=_sha384_policy,
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=TPMS_RSA_PARMS(
                    symmetric=_256_symmetric,
                    scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                    keyBits=3072,
                ),
            ),
        )
    )

    EK_RSA2048 = _ek_tuple(0x01C00002, _ek_rsa2048_template)
    EK_ECC256 = _ek_tuple(0x01C0000A, _ek_ecc256_template)
    EK_HIGH_RSA2048 = _ek_tuple(0x01C00012, _ek_high_rsa2048_template)
    EK_HIGH_ECC256 = _ek_tuple(0x01C00014, _ek_high_ecc256_template)
    EK_HIGH_ECC384 = _ek_tuple(0x01C00016, _ek_high_ecc384_template)
    EK_HIGH_ECC521 = _ek_tuple(0x01C00018, _ek_high_ecc521_template)
    EK_HIGH_ECCSM2P521 = _ek_tuple(0x01C0001A, _ek_high_eccsm2p521_template)
    EK_HIGH_RSA3072 = _ek_tuple(0x01C0001C, _ek_high_rsa3072_template)
    EK_HIGH_RSA4096 = _ek_tuple(0x01C0001E, _ek_high_rsa4096_template)
