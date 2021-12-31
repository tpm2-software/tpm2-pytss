#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2
import itertools
import unittest

from tpm2_pytss import *
from base64 import b64decode

rsa_parent_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0FeMzAfnskx8eZYICdqURfwRhcgAWHkanaDZQXAMsKyBwkov
yso31lhQQpjghFv1hzxy9z9yvcE+7LnFWbTnhWH2PPYyR87iM6eaW9wGdaFLMX5R
8xbYG1ZJYsBOfiS4LauEHDYaAsYL9uv/5K0Dw2d/LSxzbv+9+EC3AomICZsf7m1B
BVQNvtWHaPBHH+19JGtGRg8KRBWRqnrzrx6WwpGtmHVNPJwOr5hz3FtOWj99STKc
oow5EIR44lrzg4dDcpyi4vWiustdZJm2j2iHKMfGu37r/mMDPjKNxY1YZQS5B8s5
lgxp76UBAfTm3mttyH1K79eoplgkA+qBglVqQQIDAQABAoIBAQCsA/0t4ED+x4Pm
Z2dPq3bMqahWCqGuap79EncOPlNb87JXFiWLi5a6lMP/mHWXEs4P0GsjlPFJlqo7
jc5RmLmnORCzmJo/C6Nb/r/FpE55BKkuvhsvV+cp+v4wWJL2N58RphE3sbucGqR6
RLRMvETlKyinxZGxTdothFEV+TOmqT4c3YXUyxTZj74oh+ovl22xopehxz/g9QwK
VdZa2bs9p5gxUeYlE3BQTt/YQAXDxPp2kTnWf8CjQ+f1YOlx+1OVJVaVPk5d3/8U
7CK5ljZoB5y11AYT11cxlqwphlF3ePJYIuTQHRldCO2Z7fv2GFJnVqKH+eu2/4AT
94RpHpyBAoGBAO1fOV0QL7ZQk0pJlY0yETrfZRkLcUM9lFzWnF8N/zfv4CcawZpw
PvSU5tTSnF/aYJn94KSKeZ/CiIJog4metlHNIc6qZBVTvh3lOGndib9YjLQ0j/Ru
gYITCMmffe74+RTD4yTmbCttoay3DzIX+rK9RMEg7SDRrHxmsWRoZzKpAoGBAOCx
HfG+FiZgJdWkelOgSBWG+9tcNmKyV+1wLR0XDx+Ung/0IWfhov4im6sPKKmKOALk
A2cKKkcByr57Y57oBS1oT8489G8rgR4hJlBZOU40N8HRLg+9FafFH5ObS29zUeis
AP/wq2l8DOlWUfRN1W8+YzamyOdDIGdgtGn1tFHZAoGBAKjxQS6POqYTqwEQZjRc
Eg9It/efQTmONm3tANZWa/Mv8uViEbENeoExCSknzMwb7O0s2BnDxNSD7AyEvjnQ
kAqgaRNiCmFzfLhiUEhouIVLTLllP5/ElsAxM+vsbAENipnQ4XV92jb+jDcVAuew
UWmtc6XQ/XSCRrUzkcXY2LohAoGAJiNqJcJSGClxwpWsfc1S7vR+g3lfcdk7u32y
6qEjXATp32Nc2DkgZWqSabKlAEIJx9PUEAVVr7/KHhLrkeloF5EBGsyV4NjNjcOq
sTCz3WZXoHpVCy7ZIiT/exp872nvmUK42LiNH9aCioiwWHttovg/9uLQbxChy2pK
tUGTXeECgYBYh3LsYNuWHpi2tW+cO3V4XP1AGBqZy3SDKD/Uk1jZPjEamkZCRDl2
9AGIGz0H+Ovfg8vzCgYj0E9KLlE63wjSsKajC+Z17+nwzvy9cFJJtqTq/7aR0niI
DoDguNqFEpw/cs8Eccbh0K43ubpLXc7xKoLGe5CF1sxEOZpYnPbyoA==
-----END RSA PRIVATE KEY-----
"""

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    load_ssh_private_key,
)


class TypesTest(unittest.TestCase):
    def test_TPML_PCR_SELECTION_parse_2_banks_all_friendly(self):
        pcr_sels = TPML_PCR_SELECTION.parse("sha1:3,4+sha256:all")

        self.assertEqual(pcr_sels.count, 2)

        self.assertEqual(pcr_sels.pcrSelections[0].hash, TPM2_ALG.SHA1)
        self.assertEqual(pcr_sels.pcrSelections[0].sizeofSelect, 3)
        # bits 3 and 4 should be set
        self.assertEqual(pcr_sels.pcrSelections[0].pcrSelect[0], (1 << 3 | 1 << 4))
        self.assertEqual(pcr_sels.pcrSelections[0].pcrSelect[1], 0)
        self.assertEqual(pcr_sels.pcrSelections[0].pcrSelect[2], 0)
        self.assertEqual(pcr_sels.pcrSelections[0].pcrSelect[3], 0)

        self.assertEqual(pcr_sels.pcrSelections[1].hash, TPM2_ALG.SHA256)
        self.assertEqual(pcr_sels.pcrSelections[1].sizeofSelect, 3)
        # All bits should be set
        self.assertEqual(pcr_sels.pcrSelections[1].pcrSelect[0], 255)
        self.assertEqual(pcr_sels.pcrSelections[1].pcrSelect[1], 255)
        self.assertEqual(pcr_sels.pcrSelections[1].pcrSelect[2], 255)
        self.assertEqual(pcr_sels.pcrSelections[1].pcrSelect[3], 0)

    def test_TPML_PCR_SELECTION_parse_2_banks_mixed(self):

        pcr_sels = TPML_PCR_SELECTION.parse("sha256:16,17,18+0x0b:16,17,18")

        self.assertEqual(pcr_sels.count, 2)

        for i in range(0, pcr_sels.count):
            self.assertEqual(pcr_sels.pcrSelections[i].hash, TPM2_ALG.SHA256)
            self.assertEqual(pcr_sels.pcrSelections[i].sizeofSelect, 3)
            # bits 16, 17 and 18 should be set
            self.assertEqual(pcr_sels.pcrSelections[i].pcrSelect[0], 0)
            self.assertEqual(pcr_sels.pcrSelections[i].pcrSelect[1], 0)
            # offset by 16 since the third byte is index 16 to 24 inclusive
            self.assertEqual(
                pcr_sels.pcrSelections[i].pcrSelect[2], (1 << 0 | 1 << 1 | 1 << 2)
            )
            self.assertEqual(pcr_sels.pcrSelections[i].pcrSelect[3], 0)

    def test_TPML_PCR_SELECTION_parse_None(self):

        pcr_sels = TPML_PCR_SELECTION.parse(None)

        self.assertEqual(pcr_sels.count, 0)

    def test_TPML_PCR_SELECTION_parse_empty_string(self):

        pcr_sels = TPML_PCR_SELECTION.parse("")

        self.assertEqual(pcr_sels.count, 0)

    def test_TPML_PCR_SELECTION_parse_plus_only(self):

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("+")

    def test_TPML_PCR_SELECTION_parse_plus_multiple(self):

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("+++")

    def test_TPML_PCR_SELECTION_parse_plus_unbalanced(self):

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("sha256:1+")

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("+sha256:1")

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("+sha256:1+")

    def test_TPML_PCR_SELECTION_parse_gibberish(self):

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("gibberish value")

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("foo+")

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("+bar")

        with self.assertRaises(ValueError):
            TPML_PCR_SELECTION.parse("sha256:1+bar")

    def test_TPML_PCR_SELECTION_from_TPMS_PCR_SELECTION_list(self):

        first = TPMS_PCR_SELECTION.parse("sha512:1, 7, 8, 12, 18, 24")
        second = TPMS_PCR_SELECTION.parse("sha384:all")
        third = TPMS_PCR_SELECTION.parse("sha1:1,3")

        pcr_sels = TPML_PCR_SELECTION(pcrSelections=[first, second, third])
        self.assertEqual(pcr_sels.count, 3)

        x = pcr_sels.pcrSelections[0]
        self.assertEqual(x.hash, TPM2_ALG.SHA512)
        self.assertEqual(x.sizeofSelect, 3)

        self.assertEqual(x.pcrSelect[0], (1 << 1 | 1 << 7))
        self.assertEqual(x.pcrSelect[1], (1 << 0 | 1 << 4))
        self.assertEqual(x.pcrSelect[2], (1 << 2))
        self.assertEqual(x.pcrSelect[3], (1 << 0))

        x = pcr_sels.pcrSelections[1]
        self.assertEqual(x.hash, TPM2_ALG.SHA384)
        self.assertEqual(x.sizeofSelect, 3)
        # All bits should be set
        self.assertEqual(x.pcrSelect[0], 255)
        self.assertEqual(x.pcrSelect[1], 255)
        self.assertEqual(x.pcrSelect[2], 255)
        self.assertEqual(x.pcrSelect[3], 0)

        x = pcr_sels.pcrSelections[2]
        self.assertEqual(x.hash, TPM2_ALG.SHA1)
        self.assertEqual(x.sizeofSelect, 3)
        # All bits should be set
        self.assertEqual(x.pcrSelect[0], (1 << 1 | 1 << 3))
        self.assertEqual(x.pcrSelect[1], 0)
        self.assertEqual(x.pcrSelect[2], 0)
        self.assertEqual(x.pcrSelect[3], 0)

    def test_TPMS_PCR_SELECTION(self):
        x = TPMS_PCR_SELECTION()
        self.assertEqual(x.hash, 0)
        self.assertEqual(x.sizeofSelect, 0)
        self.assertEqual(x.pcrSelect[0], 0)
        self.assertEqual(x.pcrSelect[1], 0)
        self.assertEqual(x.pcrSelect[2], 0)
        self.assertEqual(x.pcrSelect[3], 0)

        with self.assertRaises(ValueError) as e:
            TPMS_PCR_SELECTION(pcrs=(1, 2, 3))
        self.assertEqual(str(e.exception), "hash and pcrs MUST be specified")

        x = TPMS_PCR_SELECTION(
            hash=TPM2_ALG.SHA256, sizeofSelect=2, pcrSelect=b"\xFF" * 2
        )
        self.assertEqual(x.hash, TPM2_ALG.SHA256)
        self.assertEqual(x.sizeofSelect, 2)
        self.assertEqual(x.pcrSelect[0], 0xFF)
        self.assertEqual(x.pcrSelect[1], 0xFF)
        self.assertEqual(x.pcrSelect[2], 0)
        self.assertEqual(x.pcrSelect[3], 0)

    def test_TPMS_PCR_SELECTION_parse(self):

        x = TPMS_PCR_SELECTION.parse("sha512:1, 7, 8, 12, 18, 24")
        self.assertEqual(x.hash, TPM2_ALG.SHA512)
        self.assertEqual(x.sizeofSelect, 3)

        self.assertEqual(x.pcrSelect[0], (1 << 1 | 1 << 7))
        self.assertEqual(x.pcrSelect[1], (1 << 0 | 1 << 4))
        self.assertEqual(x.pcrSelect[2], (1 << 2))
        self.assertEqual(x.pcrSelect[3], (1 << 0))

    def test_TPMS_PCR_SELECTION_parse_None(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse(None)

    def test_TPMS_PCR_SELECTION_parse_empty(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse("")

    def test_TPMS_PCR_SELECTION_parse_out_of_bounds_pcr(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse("sha256:42")

    def test_TPMS_PCR_SELECTION_parse_malformed(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse("this is gibberish")

    def test_TPMS_PCR_SELECTION_parse_only_colon(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse(":")

    def test_TPMS_PCR_SELECTION_parse_only_bank_and_colon(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse("sha256:")

    def test_TPMS_PCR_SELECTION_parse_bank_and_garbage(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse("sha256:foo")

    def test_TPMS_PCR_SELECTION_parse_multiple_colons(self):

        with self.assertRaises(ValueError):
            TPMS_PCR_SELECTION.parse(":::")

    def test_TPM2B_PUBLIC(self):

        # Test setting
        inPublic = TPM2B_PUBLIC()

        publicArea = inPublic.publicArea

        publicArea.type = TPM2_ALG.ECC

        inPublic.publicArea.type = TPM2_ALG.ECC
        inPublic.publicArea.nameAlg = TPM2_ALG.SHA1
        inPublic.publicArea.objectAttributes = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )

        inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDSA
        inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = (
            TPM2_ALG.SHA256
        )
        inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC.NIST_P256

        # test getting
        self.assertEqual(publicArea.type, TPM2_ALG.ECC)
        self.assertEqual(inPublic.publicArea.nameAlg, TPM2_ALG.SHA1)
        self.assertEqual(
            inPublic.publicArea.objectAttributes,
            (
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
            ),
        )

        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDSA
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg,
            TPM2_ALG.SHA256,
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.NULL
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.kdf.scheme, TPM2_ALG.NULL
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.curveID, TPM2_ECC.NIST_P256
        )

    def test_TPM_OBJECT_init(self):
        pub = TPM2B_PUBLIC(publicArea=TPMT_PUBLIC(nameAlg=TPM2_ALG.SHA256))
        self.assertEqual(pub.publicArea.nameAlg, TPM2_ALG.SHA256)

        with self.assertRaises(
            AttributeError, msg="TPM2B_PUBLIC has no field by the name of badfield"
        ):
            TPM2B_PUBLIC(badfield=1)

    def test_TPM_OBJECT_init_cdata(self):
        with self.assertRaises(
            TypeError, msg="Unexpected _cdata type uint8_t, expected TPM2B_DIGEST"
        ):
            TPM2B_DIGEST(_cdata=ffi.new("uint8_t *"))

    def test_TPM2_ALG_parse(self):
        self.assertEqual(TPM2_ALG.parse("sha"), TPM2_ALG.SHA)
        self.assertEqual(TPM2_ALG.parse("sha1"), TPM2_ALG.SHA1)
        self.assertEqual(TPM2_ALG.parse("sha256"), TPM2_ALG.SHA256)
        self.assertEqual(TPM2_ALG.parse("ShA384"), TPM2_ALG.SHA384)
        self.assertEqual(TPM2_ALG.parse("SHA512"), TPM2_ALG.SHA512)

        self.assertEqual(TPM2_ALG.parse("mgf1"), TPM2_ALG.MGF1)
        self.assertEqual(TPM2_ALG.parse("RSaes"), TPM2_ALG.RSAES)
        self.assertEqual(TPM2_ALG.parse("ECDH"), TPM2_ALG.ECDH)
        self.assertEqual(TPM2_ALG.parse("SHA3_512"), TPM2_ALG.SHA3_512)

        with self.assertRaises(ValueError):
            TPM2_ALG.parse("")

        with self.assertRaises(TypeError):
            TPM2_ALG.parse(None)

        with self.assertRaises(ValueError):
            TPM2_ALG.parse("foo")

    def test_TPM_FRIENDLY_INT_bad_to_string(self):
        with self.assertRaises(ValueError) as e:
            TPM2_ALG.to_string(TPM2_ALG.LAST + 1)
        self.assertEqual(str(e.exception), "Could not match 69 to class TPM2_ALG")

    def test_ESYS_TR(self):
        self.assertEqual(ESYS_TR.parse("PCR0"), ESYS_TR.PCR0)
        self.assertEqual(ESYS_TR.parse("NONE"), ESYS_TR.NONE)
        self.assertEqual(ESYS_TR.parse("LoCkout"), ESYS_TR.LOCKOUT)
        self.assertEqual(ESYS_TR.parse("owner"), ESYS_TR.OWNER)
        self.assertEqual(ESYS_TR.parse("NuLL"), ESYS_TR.NULL)

        self.assertEqual(ESYS_TR.to_string(ESYS_TR.OWNER), "ESYS_TR.OWNER")

        with self.assertRaises(ValueError):
            ESYS_TR.parse("")

        with self.assertRaises(TypeError):
            ESYS_TR.parse(None)

        with self.assertRaises(ValueError):
            ESYS_TR.parse("foo"), TPM2_ALG.SHA512

    def test_TPM2_ECC(self):
        self.assertEqual(TPM2_ECC.parse("NONE"), TPM2_ECC.NONE)
        self.assertEqual(TPM2_ECC.parse("nist_p192"), TPM2_ECC.NIST_P192)
        self.assertEqual(TPM2_ECC.parse("BN_P256"), TPM2_ECC.BN_P256)
        self.assertEqual(TPM2_ECC.parse("sm2_P256"), TPM2_ECC.SM2_P256)

        with self.assertRaises(ValueError):
            TPM2_ECC.parse("")

        with self.assertRaises(TypeError):
            TPM2_ECC.parse(None)

        with self.assertRaises(ValueError):
            TPM2_ECC.parse("foo")

    def test_TPM2_CC(self):
        self.assertEqual(TPM2_CC.parse("NV_Increment"), TPM2_CC.NV_Increment)
        self.assertEqual(TPM2_CC.parse("PCR_Reset"), TPM2_CC.PCR_Reset)
        self.assertEqual(TPM2_CC.parse("Certify"), TPM2_CC.Certify)
        self.assertEqual(TPM2_CC.parse("UnSEAL"), TPM2_CC.Unseal)

        with self.assertRaises(ValueError):
            TPM2_CC.parse("")

        with self.assertRaises(TypeError):
            TPM2_CC.parse(None)

        with self.assertRaises(ValueError):
            TPM2_CC.parse("foo")

    def test_TPMA_OBJECT(self):
        self.assertEqual(TPMA_OBJECT.parse("FIXEDTPM"), TPMA_OBJECT.FIXEDTPM)
        self.assertEqual(
            TPMA_OBJECT.parse("ADMINwithPOLICY"), TPMA_OBJECT.ADMINWITHPOLICY
        )
        self.assertEqual(TPMA_OBJECT.parse("SIGN_ENCRYPT"), TPMA_OBJECT.SIGN_ENCRYPT)

        self.assertEqual(TPMA_OBJECT.parse("SIGN"), TPMA_OBJECT.SIGN_ENCRYPT)
        self.assertEqual(TPMA_OBJECT.parse("ENCRYPT"), TPMA_OBJECT.SIGN_ENCRYPT)

        self.assertEqual(TPMA_OBJECT.parse("sign"), TPMA_OBJECT.SIGN_ENCRYPT)
        self.assertEqual(TPMA_OBJECT.parse("encrypt"), TPMA_OBJECT.SIGN_ENCRYPT)

        self.assertEqual(TPMA_OBJECT.parse("siGN"), TPMA_OBJECT.SIGN_ENCRYPT)
        self.assertEqual(TPMA_OBJECT.parse("enCRYpt"), TPMA_OBJECT.SIGN_ENCRYPT)

        self.assertEqual(
            TPMA_OBJECT.parse("sign_encrypt|ADMINWITHPOLICY|fixedTPM"),
            (
                TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.ADMINWITHPOLICY
            ),
        )

        with self.assertRaises(ValueError):
            TPMA_OBJECT.parse("")

        with self.assertRaises(TypeError):
            TPMA_OBJECT.parse(None)

        with self.assertRaises(ValueError):
            TPMA_OBJECT.parse("foo")

    def test_TPMA_NV(self):
        self.assertEqual(TPMA_NV.parse("ppwrite"), TPMA_NV.PPWRITE)
        self.assertEqual(TPMA_NV.parse("ORDerlY"), TPMA_NV.ORDERLY)
        self.assertEqual(TPMA_NV.parse("NO_DA"), TPMA_NV.NO_DA)

        self.assertEqual(
            TPMA_NV.parse("ppwrite|orderly|NO_DA"),
            (TPMA_NV.PPWRITE | TPMA_NV.ORDERLY | TPMA_NV.NO_DA),
        )

        self.assertEqual(TPMA_NV.parse("noda"), TPMA_NV.NO_DA)
        self.assertEqual(TPMA_NV.parse("NodA"), TPMA_NV.NO_DA)
        self.assertEqual(TPMA_NV.parse("NODA"), TPMA_NV.NO_DA)

        with self.assertRaises(ValueError):
            TPMA_NV.parse("")

        with self.assertRaises(TypeError):
            TPMA_NV.parse(None)

        with self.assertRaises(ValueError):
            TPMA_NV.parse("foo")

        self.assertEqual(str(TPMA_NV.NO_DA | TPM2_NT.COUNTER << 4), "noda|nt=0x1")

        self.assertEqual(TPMA_NV.parse("noda|nt=0x1").nt, TPM2_NT.COUNTER)

        with self.assertRaises(ValueError) as e:
            TPMA_NV.parse("madeup=1234")
        self.assertEqual(str(e.exception), "unknown mask type madeup")

        with self.assertRaises(ValueError) as e:
            TPMA_NV.parse("nt=0x10")
        self.assertEqual(
            str(e.exception), "value for nt is to large, got 0x10, max is 0xf"
        )

    def test_TPM2_SPEC(self):
        self.assertEqual(TPM2_SPEC.parse("Family"), TPM2_SPEC.FAMILY)
        self.assertEqual(TPM2_SPEC.parse("Level"), TPM2_SPEC.LEVEL)
        self.assertEqual(TPM2_SPEC.parse("DAY_of_YEAR"), TPM2_SPEC.DAY_OF_YEAR)

        with self.assertRaises(ValueError):
            TPM2_SPEC.parse("")

        with self.assertRaises(TypeError):
            TPM2_SPEC.parse(None)

        with self.assertRaises(ValueError):
            TPM2_SPEC.parse("foo")

    def test_TPM2_GENERATED_VALUE(self):
        self.assertEqual(
            TPM2_GENERATED_VALUE.parse("value"), TPM2_GENERATED_VALUE.VALUE
        )

        with self.assertRaises(ValueError):
            TPM2_GENERATED_VALUE.parse("")

        with self.assertRaises(TypeError):
            TPM2_GENERATED_VALUE.parse(None)

        with self.assertRaises(ValueError):
            TPM2_GENERATED_VALUE.parse("foo")

    def test_TPM2_RC(self):
        self.assertEqual(TPM2_RC.parse("Success"), TPM2_RC.SUCCESS)
        self.assertEqual(TPM2_RC.parse("HMAC"), TPM2_RC.HMAC)
        self.assertEqual(TPM2_RC.parse("NO_RESULT"), TPM2_RC.NO_RESULT)

        with self.assertRaises(ValueError):
            TPM2_RC.parse("")

        with self.assertRaises(TypeError):
            TPM2_RC.parse(None)

        with self.assertRaises(ValueError):
            TPM2_RC.parse("foo")

    def test_TPM2_EO(self):
        self.assertEqual(TPM2_EO.parse("EQ"), TPM2_EO.EQ)
        self.assertEqual(TPM2_EO.parse("unsigned_GT"), TPM2_EO.UNSIGNED_GT)
        self.assertEqual(TPM2_EO.parse("BITCLEAR"), TPM2_EO.BITCLEAR)

        with self.assertRaises(ValueError):
            TPM2_EO.parse("")

        with self.assertRaises(TypeError):
            TPM2_EO.parse(None)

        with self.assertRaises(ValueError):
            TPM2_EO.parse("foo")

    def test_TPM2_ST(self):
        self.assertEqual(TPM2_ST.parse("null"), TPM2_ST.NULL)
        self.assertEqual(TPM2_ST.parse("AUTH_SECRET"), TPM2_ST.AUTH_SECRET)
        self.assertEqual(TPM2_ST.parse("fu_manifest"), TPM2_ST.FU_MANIFEST)

        with self.assertRaises(ValueError):
            TPM2_ST.parse("")

        with self.assertRaises(TypeError):
            TPM2_ST.parse(None)

        with self.assertRaises(ValueError):
            TPM2_ST.parse("foo")

    def test_TPM2_SU(self):
        self.assertEqual(TPM2_SU.parse("clear"), TPM2_SU.CLEAR)
        self.assertEqual(TPM2_SU.parse("State"), TPM2_SU.STATE)

        with self.assertRaises(ValueError):
            TPM2_SU.parse("")

        with self.assertRaises(TypeError):
            TPM2_SU.parse(None)

        with self.assertRaises(ValueError):
            TPM2_SU.parse("foo")

    def test_TPM2_SE(self):
        self.assertEqual(TPM2_SE.parse("hmac"), TPM2_SE.HMAC)
        self.assertEqual(TPM2_SE.parse("TRiaL"), TPM2_SE.TRIAL)
        self.assertEqual(TPM2_SE.parse("POLICY"), TPM2_SE.POLICY)

        with self.assertRaises(ValueError):
            TPM2_SE.parse("")

        with self.assertRaises(TypeError):
            TPM2_SE.parse(None)

        with self.assertRaises(ValueError):
            TPM2_SE.parse("foo")

    def test_TPM2_PT(self):
        self.assertEqual(TPM2_PT.parse("none"), TPM2_PT.NONE)
        self.assertEqual(TPM2_PT.parse("GrouP"), TPM2_PT.GROUP)
        self.assertEqual(TPM2_PT.parse("FIXED"), TPM2_PT.FIXED)

        with self.assertRaises(ValueError):
            TPM2_PT.parse("")

        with self.assertRaises(TypeError):
            TPM2_PT.parse(None)

        with self.assertRaises(ValueError):
            TPM2_PT.parse("foo")

    def test_TPM2B_PUBLIC_specified_parts(self):

        attrs = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )

        templ = TPMT_PUBLIC(
            type=TPM2_ALG.ECC, nameAlg=TPM2_ALG.parse("SHA1"), objectAttributes=attrs
        )

        inPublic = TPM2B_PUBLIC(publicArea=templ)

        inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDSA
        inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = (
            TPM2_ALG.SHA256
        )
        inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC.NIST_P256

        # test getting
        self.assertEqual(inPublic.publicArea.type, TPM2_ALG.ECC)
        self.assertEqual(inPublic.publicArea.nameAlg, TPM2_ALG.SHA1)
        self.assertEqual(
            inPublic.publicArea.objectAttributes,
            (
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
            ),
        )

        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDSA
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg,
            TPM2_ALG.SHA256,
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.NULL
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.kdf.scheme, TPM2_ALG.NULL
        )
        self.assertEqual(
            inPublic.publicArea.parameters.eccDetail.curveID, TPM2_ECC.NIST_P256
        )

    def test_marshal(self):
        pb = TPM2B_PUBLIC()
        pb.publicArea.authPolicy.buffer = b"password"
        b = pb.publicArea.authPolicy.marshal()
        self.assertEqual(b, b"\x00\x08password")

    def test_unmarshal(self):
        buf = b"\x00\x05test1"
        d, offset = TPM2B_DIGEST.unmarshal(buf)
        self.assertEqual(offset, 7)
        self.assertEqual(d.size, 5)
        db = d.buffer
        self.assertEqual(db, b"test1")

    def test_unsupported_unmarshal(self):
        with self.assertRaises(RuntimeError) as e:
            TPM_OBJECT.unmarshal(b"")
        self.assertEqual(str(e.exception), "No unmarshal function found for TPM_OBJECT")

    def test_TPMT_PUBLIC_empty(self):

        templ = TPMT_PUBLIC.parse()
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.RSA)

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPMT_PUBLIC_parse_rsa(self):

        templ = TPMT_PUBLIC.parse("rsa")
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.RSA)

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPMT_PUBLIC_parse_rsa_rsapss(self):

        templ = TPMT_PUBLIC.parse(
            "rsa:rsapss:null", TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.RSA)

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.RSAPSS)
        self.assertEqual(
            templ.parameters.asymDetail.scheme.details.anySig.hashAlg, TPM2_ALG.SHA256
        )

        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPMT_PUBLIC_parse_rsa_keysizes(self):

        for keysize in [1024, 2048, 3072, 4096]:
            templ = TPMT_PUBLIC.parse(f"rsa{keysize}")
            self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
            self.assertEqual(
                templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
            )

            self.assertEqual(templ.type, TPM2_ALG.RSA)
            self.assertEqual(templ.parameters.rsaDetail.keyBits, keysize)
            self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

            self.assertEqual(
                templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL
            )

    def test_TPMT_PUBLIC_parse_rsa2048_(self):

        templ = TPMT_PUBLIC.parse("rsa2048:")
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPMT_PUBLIC_parse_rsaall_all(self):

        rsasizes = [1024, 2048, 3072, 4096]
        keysizes = [128, 192, 256]
        modes = ["cfb", "cbc", "ofb", "ctr", "ecb"]

        for rsasize, keysize, mode, in list(
            itertools.product(rsasizes, keysizes, modes)
        ):
            templ = TPMT_PUBLIC.parse(
                f"rsa{rsasize}:rsassa-sha384:aes{keysize}{mode}",
                TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )
            self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
            self.assertEqual(
                templ.objectAttributes,
                TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )

            self.assertEqual(templ.type, TPM2_ALG.RSA)
            self.assertEqual(templ.parameters.rsaDetail.exponent, 0)
            self.assertEqual(templ.parameters.rsaDetail.keyBits, rsasize)
            self.assertEqual(
                templ.parameters.asymDetail.scheme.details.anySig.hashAlg,
                TPM2_ALG.SHA384,
            )
            self.assertEqual(templ.parameters.rsaDetail.symmetric.keyBits.aes, keysize)
            self.assertEqual(
                templ.parameters.rsaDetail.symmetric.mode.sym, TPM2_ALG.parse(mode)
            )
            self.assertEqual(
                templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.AES
            )

    def test_TPMT_PUBLIC_parse_rsa2048_restricted(self):

        templ = TPMT_PUBLIC.parse(alg="rsa2048", objectAttributes="RESTRICTED")
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(templ.objectAttributes, TPMA_OBJECT.RESTRICTED)

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.rsaDetail.symmetric.keyBits.aes, 128)
        self.assertEqual(templ.parameters.rsaDetail.symmetric.mode.sym, TPM2_ALG.CFB)
        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.AES)

    def test_TPMT_PUBLIC_parse_bad_params(self):
        message = "Expected keybits for RSA to be one of ['1024', '2048', '3072', '4096'], got:\"512\""
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse(alg="rsa512")

        message = "Expected bits to be one of ['128', '192', '256'], got: \"512\""
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse(alg="rsa2048:aes512")

        message = "Expected mode to be one of ['cfb', 'cbc', 'ofb', 'ctr', 'ecb'], got: \"yyy\""
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse(alg="rsa2048:aes256yyy")

        message = "Expected object prefix to be one of ('rsa', 'ecc', 'aes', 'camellia', 'xor', 'hmac', 'keyedhash'), got: \"unsupported\""
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse("unsupported")

        message = 'Expected symmetric detail to be null or start with one of aes, camellia, got: "hmac"'
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse("rsa2048:hmac")

        message = 'Keyedhash objects cannot have asym detail, got: "aes128"'
        with self.assertRaises(ValueError, msg=message) as e:
            TPMT_PUBLIC.parse("hmac:aes128")

    def test_TPMT_PUBLIC_parse_ecc_ecdaa4_sha256(self):

        # scheme is set, so we need to be smarter about the attributes we use
        templ = TPMT_PUBLIC.parse(
            f"ecc:ecdaa4-sha256",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.ECC)
        self.assertEqual(templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.NIST_P256)
        self.assertEqual(templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDAA)
        self.assertEqual(templ.parameters.eccDetail.scheme.details.ecdaa.count, 4)
        self.assertEqual(
            templ.parameters.eccDetail.scheme.details.ecdaa.hashAlg, TPM2_ALG.SHA256
        )
        self.assertEqual(
            templ.parameters.asymDetail.scheme.details.anySig.hashAlg, TPM2_ALG.SHA256
        )

        # since this was restricted it should set the symmetric details to aes128cfb
        self.assertEqual(templ.parameters.asymDetail.symmetric.keyBits.aes, 128)
        self.assertEqual(templ.parameters.asymDetail.symmetric.mode.sym, TPM2_ALG.CFB)
        self.assertEqual(templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.AES)

    def test_TPMT_PUBLIC_parse_ecc_ecdaa4(self):

        # scheme is set, so we need to be smarter about the attributes we use
        templ = TPMT_PUBLIC.parse(
            f"ecc:ecdaa4",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.ECC)
        self.assertEqual(templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.NIST_P256)
        self.assertEqual(templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDAA)
        self.assertEqual(templ.parameters.eccDetail.scheme.details.ecdaa.count, 4)
        self.assertEqual(
            templ.parameters.eccDetail.scheme.details.ecdaa.hashAlg, TPM2_ALG.SHA256
        )
        self.assertEqual(
            templ.parameters.asymDetail.scheme.details.anySig.hashAlg, TPM2_ALG.SHA256
        )

        # since this was restricted it should set the symmetric details to aes128cfb
        self.assertEqual(templ.parameters.asymDetail.symmetric.keyBits.aes, 128)
        self.assertEqual(templ.parameters.asymDetail.symmetric.mode.sym, TPM2_ALG.CFB)
        self.assertEqual(templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.AES)

    def test_TPMT_PUBLIC_parse_ecda_ecdh_sha384(self):

        # scheme is set, so we need to be smarter about the attributes we use
        templ = TPMT_PUBLIC.parse(
            "ecc:ecdh-sha384",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
        )
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.ECC)
        self.assertEqual(templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.NIST_P256)
        self.assertEqual(templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDH)
        self.assertEqual(
            templ.parameters.eccDetail.scheme.details.ecdh.hashAlg, TPM2_ALG.SHA384
        )
        self.assertEqual(
            templ.parameters.asymDetail.scheme.details.anySig.hashAlg, TPM2_ALG.SHA384
        )

        # since this was restricted it should set the symmetric details to aes128cfb
        self.assertEqual(templ.parameters.asymDetail.symmetric.keyBits.aes, 128)
        self.assertEqual(templ.parameters.asymDetail.symmetric.mode.sym, TPM2_ALG.CFB)
        self.assertEqual(templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.AES)

    def test_TPMT_PUBLIC_parse_ecda_ecdsa_ecdh_ecschnorr(self):

        # scheme is set, so we need to be smarter about the attributes we use
        for scheme in ["ecdsa", "ecdh", "ecschnorr"]:
            templ = TPMT_PUBLIC.parse(
                f"ecc:{scheme}",
                objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )
            self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
            self.assertEqual(
                templ.objectAttributes,
                TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )

            self.assertEqual(templ.type, TPM2_ALG.ECC)
            self.assertEqual(
                templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.NIST_P256
            )
            self.assertEqual(
                templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.parse(scheme)
            )
            self.assertEqual(
                templ.parameters.asymDetail.scheme.details.anySig.hashAlg,
                TPM2_ALG.SHA256,
            )

            # since this was restricted it should set the symmetric details to aes128cfb
            self.assertEqual(templ.parameters.asymDetail.symmetric.keyBits.aes, 128)
            self.assertEqual(
                templ.parameters.asymDetail.symmetric.mode.sym, TPM2_ALG.CFB
            )
            self.assertEqual(
                templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.AES
            )

    def test_TPMT_PUBLIC_parse_ecc_all(self):

        curves = ["192", "224", "256", "384", "521"]
        keysizes = [128, 192, 256]
        modes = ["cfb", "cbc", "ofb", "ctr", "ecb"]
        schemes = [
            "ecdsa",
            "ecdh",
            "ecschnorr",
            "ecdsa-sha",
            "ecdh-sha384",
            "ecschnorr-sha512",
        ]

        for curve, keysize, mode, scheme in list(
            itertools.product(curves, keysizes, modes, schemes)
        ):
            templ = TPMT_PUBLIC.parse(
                f"ecc{curve}:{scheme}:aes{keysize}{mode}",
                objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )
            self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
            self.assertEqual(
                templ.objectAttributes,
                TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )

            hunks = scheme.split("-")
            scheme = hunks[0]
            scheme_halg = TPM2_ALG.parse(hunks[1] if len(hunks) > 1 else "sha256")

            self.assertEqual(templ.type, TPM2_ALG.ECC)
            self.assertEqual(
                templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.parse(curve)
            )
            self.assertEqual(
                templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.parse(scheme)
            )
            self.assertEqual(
                templ.parameters.asymDetail.scheme.details.anySig.hashAlg, scheme_halg
            )

            self.assertEqual(templ.parameters.asymDetail.symmetric.keyBits.aes, keysize)
            self.assertEqual(
                templ.parameters.asymDetail.symmetric.mode.sym, TPM2_ALG.parse(mode)
            )
            self.assertEqual(
                templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.AES
            )

    def test_TPMT_PUBLIC_parse_xor(self):
        templ = TPMT_PUBLIC.parse(alg="xor")
        self.assertEqual(templ.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(templ.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.XOR)
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg,
            TPM2_ALG.SHA256,
        )
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf,
            TPM2_ALG.KDF1_SP800_108,
        )

        templ = TPMT_PUBLIC.parse(alg="xor:sha512")
        self.assertEqual(templ.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(templ.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.XOR)
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg,
            TPM2_ALG.SHA512,
        )
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf,
            TPM2_ALG.KDF1_SP800_108,
        )

    def test_TPMT_PUBLIC_parse_keyedhash(self):

        templ = TPMT_PUBLIC.parse(alg="keyedhash")
        self.assertEqual(templ.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(templ.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.NULL)

        # should fail, cannot have additional specifiers
        with self.assertRaises(ValueError):
            templ = TPMT_PUBLIC.parse(alg="keyedhash:sha512")

    def test_TPMT_PUBLIC_parse_hmac(self):
        templ = TPMT_PUBLIC.parse(alg="hmac")
        self.assertEqual(templ.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(templ.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.HMAC)
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.hmac.hashAlg,
            TPM2_ALG.SHA256,
        )

        templ = TPMT_PUBLIC.parse(alg="hmac:sha512")
        self.assertEqual(templ.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(templ.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.HMAC)
        self.assertEqual(
            templ.parameters.keyedHashDetail.scheme.details.hmac.hashAlg,
            TPM2_ALG.SHA512,
        )

    def test_TPMT_PUBLIC_parse_ecc_plain(self):

        templ = TPMT_PUBLIC.parse(alg="ecc")

        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)

        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.ECC)
        self.assertEqual(templ.parameters.eccDetail.curveID, TPM2_ECC_CURVE.NIST_P256)

        self.assertEqual(templ.parameters.eccDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.asymDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPMT_PUBLIC_parse_ecc_camellia(self):
        templ = TPMT_PUBLIC.parse(alg="ecc:camellia128cfb")
        self.assertEqual(
            templ.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.CAMELLIA
        )
        self.assertEqual(templ.parameters.eccDetail.symmetric.keyBits.camellia, 128)
        self.assertEqual(
            templ.parameters.eccDetail.symmetric.mode.camellia, TPM2_ALG.CFB
        )

    def test_TPMT_PUBLIC_parse_rsa_oaep(self):
        templ = TPMT_PUBLIC.parse(
            "rsa2048:oaep-sha512",
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
            ^ TPMA_OBJECT.SIGN_ENCRYPT,
        )
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.OAEP)
        self.assertEqual(
            templ.parameters.asymDetail.scheme.details.oaep.hashAlg, TPM2_ALG.SHA512
        )
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)

    def test_TPMT_PUBLIC_parse_rsa_rsaes(self):
        templ = TPMT_PUBLIC.parse(
            "rsa2048:rsaes",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
            ^ TPMA_OBJECT.SIGN_ENCRYPT,
        )
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.RSAES)

    def test_TPMT_PUBLIC_parse_camellia(self):
        templ = TPMT_PUBLIC.parse("camellia256cfb")
        self.assertEqual(templ.type, TPM2_ALG.SYMCIPHER)
        self.assertEqual(templ.parameters.symDetail.sym.algorithm, TPM2_ALG.CAMELLIA)
        self.assertEqual(templ.parameters.symDetail.sym.keyBits.sym, 256)
        self.assertEqual(templ.parameters.symDetail.sym.mode.sym, TPM2_ALG.CFB)

    def test_TPML_ALG_parse_none(self):
        with self.assertRaises(ValueError):
            TPML_ALG.parse(None)

    def test_TPML_ALG_parse_empty(self):
        with self.assertRaises(ValueError):
            TPML_ALG.parse("")

    def test_TPML_ALG_parse_commas(self):
        with self.assertRaises(ValueError):
            TPML_ALG.parse(",,,,,,")

    def test_TPML_ALG_parse_single(self):
        a = TPML_ALG.parse("rsa")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0], TPM2_ALG.RSA)

    def test_TPML_ALG_parse_double(self):
        a = TPML_ALG.parse("rsa,aes")
        self.assertEqual(len(a), 2)
        self.assertEqual(a[0], TPM2_ALG.RSA)
        self.assertEqual(a[1], TPM2_ALG.AES)

    def test_TPML_ALG_parse_double_spaces(self):
        a = TPML_ALG.parse(" rsa , aes")
        self.assertEqual(len(a), 2)
        self.assertEqual(a[0], TPM2_ALG.RSA)
        self.assertEqual(a[1], TPM2_ALG.AES)

    def test_TPML_ALG_parse_double_mixed_case(self):
        a = TPML_ALG.parse("RSa,aEs")
        self.assertEqual(len(a), 2)
        self.assertEqual(a[0], TPM2_ALG.RSA)
        self.assertEqual(a[1], TPM2_ALG.AES)

    def test_TPML_ALG_parse_double_extra_commas(self):
        a = TPML_ALG.parse(",RSa,,aEs,,")
        self.assertEqual(len(a), 2)
        self.assertEqual(a[0], TPM2_ALG.RSA)
        self.assertEqual(a[1], TPM2_ALG.AES)

    def test_TPML_ALG_parse_bad(self):

        with self.assertRaises(ValueError):
            TPML_ALG.parse("not,real,alg")

        with self.assertRaises(ValueError):
            TPML_ALG.parse("jfghsjhdgfdhg")

        with self.assertRaises(ValueError):
            TPML_ALG.parse("aes,rsa,foo")

    def test_TPML_ALG_setitem_single(self):
        t = TPML_ALG()
        t[0] = TPM2_ALG.AES
        t[2] = TPM2_ALG.CAMELLIA
        t[8] = TPM2_ALG.ECDH
        self.assertEqual(t[0], TPM2_ALG.AES)
        self.assertEqual(t[2], TPM2_ALG.CAMELLIA)
        self.assertEqual(t[8], TPM2_ALG.ECDH)
        self.assertEqual(len(t), 9)

    def test_TPML_ALG_setitem_slices(self):
        t = TPML_ALG()
        t[0:4] = [TPM2_ALG.AES, TPM2_ALG.CAMELLIA, TPM2_ALG.ECDH, TPM2_ALG.ECMQV]
        self.assertEqual(t[0], TPM2_ALG.AES)
        self.assertEqual(t[1], TPM2_ALG.CAMELLIA)
        self.assertEqual(t[2], TPM2_ALG.ECDH)
        self.assertEqual(t[3], TPM2_ALG.ECMQV)
        self.assertEqual(len(t), 4)

    def test_TPML_ALG_setitem_slices_with_step(self):
        t = TPML_ALG()
        t[0:4:2] = [TPM2_ALG.AES, TPM2_ALG.ECDH]
        self.assertEqual(t[0], TPM2_ALG.AES)
        self.assertEqual(t[1], 0)
        self.assertEqual(t[2], TPM2_ALG.ECDH)
        self.assertEqual(t[3], 0)
        self.assertEqual(len(t), 4)

    def test_TPML_ALG_setitem_slices_with_too_many_unpack(self):

        t = TPML_ALG()
        with self.assertRaises(ValueError):
            t[0:4:2] = [TPM2_ALG.AES, TPM2_ALG.ECDH, TPM2_ALG.CAMELLIA]

    def test_TPML_ALG_setitem_slices_with_too_few_unpack(self):

        t = TPML_ALG()
        with self.assertRaises(ValueError):
            t[0:4:2] = [TPM2_ALG.AES]

    def test_TPML_ALG_setitem_slices_set_list_with_int_key(self):

        t = TPML_ALG()
        with self.assertRaises(TypeError):
            t[0] = [TPM2_ALG.AES]

    def test_TPML_PCR_SELECTION_setattr_slice(self):
        t = TPML_PCR_SELECTION()
        x = [
            TPMS_PCR_SELECTION.parse("sha256:1,2,3"),
            TPMS_PCR_SELECTION.parse("sha384:0,5,6"),
            TPMS_PCR_SELECTION.parse("sha512:7"),
        ]

        t[0:3] = x
        self.assertEqual(t[0].hash, TPM2_ALG.SHA256)
        self.assertEqual(t[0].pcrSelect[0], 14)
        self.assertEqual(t[1].hash, TPM2_ALG.SHA384)
        self.assertEqual(t[1].pcrSelect[0], 97)
        self.assertEqual(t[2].hash, TPM2_ALG.SHA512)
        self.assertEqual(t[2].pcrSelect[0], 128)
        self.assertEqual(len(t), 3)

    def test_TPML_PCR_SELECTION_iterator(self):
        pcrselections = TPML_PCR_SELECTION.parse("sha256:1,2,3+sha384:0,5,6+sha512:7")

        self.assertEqual(len(pcrselections), 3)

        for i, selection in enumerate(pcrselections):

            if i == 0:
                self.assertEqual(selection.hash, TPM2_ALG.SHA256)
                self.assertEqual(selection.pcrSelect[0], 14)
            elif i == 1:
                self.assertEqual(selection.hash, TPM2_ALG.SHA384)
                self.assertEqual(selection.pcrSelect[0], 97)
            elif i == 2:
                self.assertEqual(selection.hash, TPM2_ALG.SHA512)
                self.assertEqual(selection.pcrSelect[0], 128)

        # make sure state resets
        for i, selection in enumerate(pcrselections):

            if i == 0:
                self.assertEqual(selection.hash, TPM2_ALG.SHA256)
                self.assertEqual(selection.pcrSelect[0], 14)
            elif i == 1:
                self.assertEqual(selection.hash, TPM2_ALG.SHA384)
                self.assertEqual(selection.pcrSelect[0], 97)
            elif i == 2:
                self.assertEqual(selection.hash, TPM2_ALG.SHA512)
                self.assertEqual(selection.pcrSelect[0], 128)

    def test_TPML_PCR_SELECTION_bad_selections(self):
        toomany = "+".join([f"{x}" for x in range(0, 17)])
        with self.assertRaises(
            ValueError, msg="PCR Selection list greater than 16, got 17"
        ):
            TPML_PCR_SELECTION.parse(toomany)

    def test_TPM2B_AUTH_empty(self):
        x = TPM2B_AUTH()
        self.assertEqual(x.size, 0)

    def test_TPM2B_AUTH_bad_fields(self):
        with self.assertRaises(AttributeError):
            TPM2B_AUTH(foo="bar")

    def test_TPM2B_AUTH_empty_str(self):
        x = TPM2B_AUTH("")
        self.assertEqual(x.size, 0)

    def test_TPM2B_AUTH_set_str(self):
        # You can send it in as a string
        x = TPM2B_AUTH("password")
        self.assertEqual(x.size, 8)
        # but you get bytes back
        self.assertEqual(x.buffer, b"password")
        self.assertEqual(bytes(x), b"password")

    def test_TPMS_SENSITIVE_CREATE_with_string(self):

        x = TPMS_SENSITIVE_CREATE(userAuth="password")
        p = str(x.userAuth)
        self.assertEqual(p, binascii.hexlify("password".encode()).decode())

    def test_TPM2B_SIMPLE_OBJECT(self):
        bob = b"bunchofbytes"
        dig = TPM2B_NAME(bob)
        self.assertEqual(dig.name, bob)
        self.assertEqual(len(dig), len(bob))

        for i in range(0, len(dig)):
            self.assertEqual(dig[i], bob[i])

        with self.assertRaises(IndexError):
            dig[len(dig)]

        self.assertEqual(dig[0:3], b"bun")

        self.assertEqual(dig[60:64], b"")

        with self.assertRaises(TypeError):
            dig["str"]

        i = 0
        for b in dig:
            self.assertEqual(b, bob[i])
            i = i + 1

        b = bytes(dig)
        self.assertEqual(b, bob)

        self.assertEqual(dig, bob)
        self.assertNotEqual(dig, "pinchofbytes")

        sdig = TPM2B_DIGEST(bob)
        self.assertEqual(dig, sdig)

        with self.assertRaises(AttributeError):
            dig.size = 1
        with self.assertRaises(TypeError):
            dig.name[0] = b"\x00"

        with self.assertRaises(AttributeError) as e:
            TPM2B_DIGEST(size=12)
        self.assertEqual(str(e.exception), "size is read only")

        # This checks that TPM2B_SIMPLE_OBJECTs __setattr__ calls TPM_OBJECTs __setattr__
        dig.nosuchfield = b"1234"
        self.assertEqual(dig.nosuchfield, b"1234")

    def test_TPMS_ECC_POINT(self):

        x = b"12345678"
        y = b"87654321"
        t = TPMS_ECC_POINT(x=x, y=y)
        self.assertEqual(bytes(t.x), x)
        self.assertEqual(bytes(t.y), y)
        self.assertEqual(len(t.x), len(x))
        self.assertEqual(len(t.y), len(y))

        self.assertEqual(str(t.x), binascii.hexlify(x).decode())
        self.assertEqual(str(t.y), binascii.hexlify(y).decode())

        x = "thisisareallylongstringx"
        y = "thisisareallylongstringy"
        t = TPMS_ECC_POINT(x=x, y=y)
        self.assertEqual(bytes(t.x), x.encode())
        self.assertEqual(bytes(t.y), y.encode())
        self.assertEqual(len(t.x), len(x.encode()))
        self.assertEqual(len(t.y), len(y.encode()))

        self.assertEqual(str(t.x), binascii.hexlify(x.encode()).decode())
        self.assertEqual(str(t.y), binascii.hexlify(y.encode()).decode())

        x = b"12345678"
        y = b"87654321"
        t = TPMS_ECC_POINT()
        t.x = x
        t.y = y
        self.assertEqual(bytes(t.x), x)
        self.assertEqual(bytes(t.y), y)
        self.assertEqual(len(t.x), len(x))
        self.assertEqual(len(t.y), len(y))

        self.assertEqual(str(t.x), binascii.hexlify(x).decode())
        self.assertEqual(str(t.y), binascii.hexlify(y).decode())

    def test_scalar_data(self):

        x = b"12345678"
        y = b"87654321"
        t = TPM2B_ECC_POINT(TPMS_ECC_POINT(x=x, y=y))

        TPM2B_ECC_POINT(t.point)

    def test_copy_constructor(self):

        x = b"12345678"
        y = b"87654321"
        t1 = TPM2B_ECC_POINT(TPMS_ECC_POINT(x=x, y=y))

        t2 = TPM2B_ECC_POINT(t1)

        self.assertEqual(bytes(t1.point.x), bytes(t2.point.x))
        self.assertEqual(bytes(t1.point.y), bytes(t2.point.y))
        self.assertNotEqual(t1._cdata, t2._cdata)

        templ = TPMT_PUBLIC.parse(alg="ecc")
        templ2 = TPMT_PUBLIC(templ)

        self.assertEqual(templ.type, TPM2_ALG.ECC)
        self.assertEqual(templ2.type, TPM2_ALG.ECC)

        templ.type = TPM2_ALG.RSA
        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ2.type, TPM2_ALG.ECC)

        templ2.type = TPM2_ALG.KEYEDHASH
        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ2.type, TPM2_ALG.KEYEDHASH)

    def test_TPM_FRIENDLY_INT_iterator(self):
        self.assertNotEqual(len(list(TPM2_CC.iterator())), 0)

    def test_TPM_FRIENDLY_INT_contains(self):
        self.assertTrue(TPM2_CC.contains(TPM2_CC.AC_Send))

    def test_TPM2B_PUBLIC_parse(self):

        tpm2b = TPM2B_PUBLIC.parse("rsa")
        templ = tpm2b.publicArea
        self.assertEqual(templ.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            templ.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )

        self.assertEqual(templ.type, TPM2_ALG.RSA)

        self.assertEqual(templ.type, TPM2_ALG.RSA)
        self.assertEqual(templ.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(templ.parameters.asymDetail.scheme.scheme, TPM2_ALG.NULL)

        self.assertEqual(templ.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)

    def test_TPML_DIGEST_VALUES(self):

        sha1 = b"0123456789abcdeffedc"
        sha256 = b"0123456789abcdeffedcba9876543210"

        digests = TPML_DIGEST_VALUES(
            [
                TPMT_HA(hashAlg=TPM2_ALG.SHA1, digest=TPMU_HA(sha1=sha1)),
                TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha256=sha256)),
            ]
        )

        self.assertEqual(len(digests), 2)

        self.assertEqual(digests[0].hashAlg, TPM2_ALG.SHA1)
        self.assertEqual(bytes(digests[0].digest.sha1), sha1)

        self.assertEqual(digests[1].hashAlg, TPM2_ALG.SHA256)
        self.assertEqual(bytes(digests[1].digest.sha256), sha256)

    def test_TPML_DIGEST(self):

        x = TPML_DIGEST([b"0123456789ABCDEF0123456789ABCDEF"])
        self.assertEqual(len(x), 1)
        self.assertEqual(x[0], b"0123456789ABCDEF0123456789ABCDEF")

        x = TPML_DIGEST(
            [
                "0123456789ABCDEF0123456789ABCDEF",
                b"12345678901234567890",
                TPM2B_DIGEST(b"0123456"),
            ]
        )
        self.assertEqual(len(x), 3)
        self.assertEqual(x[0], b"0123456789ABCDEF0123456789ABCDEF")
        self.assertEqual(x[1], b"12345678901234567890")
        self.assertEqual(x[2], b"0123456")

        with self.assertRaises(TypeError):
            TPML_DIGEST([object(), object()])

        with self.assertRaises(TypeError):
            TPML_DIGEST(TPML_ALG_PROPERTY())

        with self.assertRaises(TypeError):
            TPML_PCR_SELECTION(TPML_AC_CAPABILITIES())

    def test_TPMA_LOCALITY(self):

        self.assertEqual(TPMA_LOCALITY.create_extended(0), 32)
        self.assertEqual(TPMA_LOCALITY.create_extended(2), 34)
        self.assertEqual(TPMA_LOCALITY.create_extended(255 - 32), 255)

        with self.assertRaises(ValueError):
            TPMA_LOCALITY.create_extended(255 - 32 + 1)

    def test_TPMS_CONTEXT_from_tools(self):
        test_ctx = b"""utzA3gAAAAFAAAABgAAAAAAAAAAAAAOkAvIAAAAAAqIAIFNJEhgwU8zxMhuTBhSqPktXguCbMgUg
        mACnGHIlDr0mAn7QtSMsTy1hAOqPvR8LRxcCphVs1owzQuHIe1Ez4kwA5xSl2zU+xFMhuD9coN4Z
        LiRxwuxCDuQ41rqJHRpRbJKn0zj3uw/rpdkGzSKP70VlZxtTnH1TKnpA65Dhxmzt9+AqCC8oAbeT
        8ceZy9FelFZJjKQ8ik8zavDLxhy5etD4Y9IwetM6rAt6tlUqzNeR2OhJMpn3uFt4eO+qLxCifIHR
        hgpD0+ulWoCXfYA2CJIPnnHGzxx96soUyXwng7rb4fgfWaan6SXfxd/MAcRQNAR7nVsG2wTyZH3F
        cVOqXaQhdZOBXsbsoZfPu3Vne3GGc9kA6V2RuhwvTVHYj3R5eCS+9eOknsr8dHWez8Txzwk1l5lx
        xLt2AmDO7M8IyHGcI68ven5/SoXEX3nwz8mlYHLhdPnuq11GO0Ak3cARCvfvKrZIPUF+Bhkk9HHg
        725rbsSvWWi/Od+zWWqMKMX9um+PmT+xrA65+xBH0pYhv8UhYUqzEQc7eUylxXXQuQzGHTjL3XdL
        Rl9zo+WBjuBzF44E6j8c8ghdlUqCWICF/gfD8Nnfx2JT+rRcs1sz4+T3s8725ghYWmJhb+Oy+KDB
        PZQvl9F8XUpEZ3b+xJ0qBHhdhutFvqAFq2dTZLLy+sfOj61PPgz8hmCZcuc+i3OnA+73E7GXqucU
        YzRgJaptxRrMbujvIKlK/BI0OK4mGA505hLb+EjWkZ7eTkEmEyviVL5ZxeqPk3+hMArjuEy25HCN
        N7Js0AVEQzgXAQm5jdxkcNcwTR0Z46sDdntMkxslR//+0iep9EvcXLgZ/hyTkTjQkB7zKQjh3NBO
        r+ShbNtNnOUGnAYOhak3DMmOKdpBgAAAgAAA/wAWAAR53X6WF4cq4euj360A2EG67P+iZgAAAAEA
        JgAlAAQAAwByAAAABgCAABAAFIrV77jm23RSbSe0b3NqvEBvuN35"""

        ctxbytes = b64decode(test_ctx)
        ctx = TPMS_CONTEXT.from_tools(ctxbytes)

        self.assertEqual(ctx.hierarchy, lib.TPM2_RH_OWNER)
        self.assertEqual(ctx.savedHandle, 0x80000000)
        self.assertEqual(ctx.sequence, 932)
        self.assertEqual(ctx.contextBlob, ctxbytes[26:])

        badmagic = bytearray(ctxbytes)
        badmagic[0] = 1
        with self.assertRaises(ValueError):
            ctx = TPMS_CONTEXT.from_tools(badmagic)

        badversion = bytearray(ctxbytes)
        badversion[5] = 0xFF
        with self.assertRaises(ValueError):
            ctx = TPMS_CONTEXT.from_tools(badversion)

    def test_TPM_FRIENDLY_INT_str(self):
        alg = TPM2_ALG(TPM2_ALG.ECC)
        self.assertEqual(str(alg), "ecc")

        badalg = TPM2_ALG(TPM2_ALG.LAST + 1)
        self.assertEqual(str(badalg), str(TPM2_ALG.LAST + 1))

    def test_TPM_FRIENDLY_INTLIST_str(self):
        attrs = TPMA_OBJECT(
            TPMA_OBJECT.DECRYPT | TPMA_OBJECT.NODA | TPMA_OBJECT.SIGN_ENCRYPT
        )
        self.assertEqual(str(attrs), "noda|decrypt|sign")

        badattrs = TPMA_OBJECT(
            TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.NODA
            | TPMA_OBJECT.SIGN_ENCRYPT
            | 0x00090000
        )
        with self.assertRaises(ValueError) as e:
            str(badattrs)
        self.assertEqual(str(e.exception), "unnmatched values left: 0x80000")

        aw = TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD
        self.assertEqual(str(aw), "authwrite|authread")

        self.assertEqual(str(TPMA_CC()), "")

    def test_TPM_FRIENDLY_INTLIST_math(self):
        ab = abs(TPM2_ALG.RSA)
        self.assertIsInstance(ab, TPM2_ALG)
        self.assertEqual(ab, TPM2_ALG.RSA)

        add = TPM2_ALG.ERROR + 1
        self.assertIsInstance(add, TPM2_ALG)
        self.assertEqual(add, TPM2_ALG.RSA)

        a = TPMA_OBJECT.RESTRICTED & 0x10000
        self.assertIsInstance(a, TPMA_OBJECT)
        self.assertEqual(a, TPMA_OBJECT.RESTRICTED)

        ceil = TPM2_ALG.RSA.__ceil__()
        self.assertIsInstance(ceil, TPM2_ALG)
        self.assertEqual(ceil, TPM2_ALG.RSA)

        dm = divmod(TPM2_ALG.ECC, TPM2_ALG.NULL)
        self.assertIsInstance(dm[0], TPM2_ALG)
        self.assertIsInstance(dm[1], TPM2_ALG)

        floor = TPM2_ALG.RSA.__floor__()
        self.assertIsInstance(floor, TPM2_ALG)
        self.assertEqual(floor, TPM2_ALG.RSA)

        floordiv = TPM2_ALG.ECC.__floordiv__(1)
        self.assertIsInstance(floordiv, TPM2_ALG)

        inv = ~TPM2_ALG.ECC
        self.assertIsInstance(inv, TPM2_ALG)
        self.assertEqual(inv, ~int(TPM2_ALG.ECC))

        ls = TPM2_ALG.RSA << 1
        self.assertIsInstance(ls, TPM2_ALG)

        mod = TPM2_ALG.ECC % 100
        self.assertIsInstance(mod, TPM2_ALG)

        mul = TPM2_ALG.RSA * 2
        self.assertIsInstance(mul, TPM2_ALG)

        neg = -TPM2_ALG.RSA
        self.assertIsInstance(neg, TPM2_ALG)

        o = TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.FIXEDTPM
        self.assertIsInstance(o, TPMA_OBJECT)
        self.assertEqual(o, 0x2 | 0x10000)

        pos = +TPM2_ALG.RSA
        self.assertIsInstance(pos, TPM2_ALG)

        p = TPM2_ALG.RSA ** 1
        self.assertIsInstance(p, TPM2_ALG)

        radd = 1 + TPM2_ALG.NULL
        self.assertIsInstance(radd, TPM2_ALG)

        rand = 1 & TPM2_ALG.RSA
        self.assertIsInstance(rand, TPM2_ALG)

        rdv = divmod(1, TPM2_ALG.ECC)
        self.assertIsInstance(rdv[0], TPM2_ALG)
        self.assertIsInstance(rdv[1], TPM2_ALG)

        rfloordiv = 1 // TPM2_ALG.RSA
        self.assertIsInstance(rfloordiv, TPM2_ALG)

        rmod = 3 % TPM2_ALG.RSA
        self.assertIsInstance(rmod, TPM2_ALG)

        rmul = 1 * TPM2_ALG.RSA
        self.assertIsInstance(rmul, TPM2_ALG)

        r = round(TPM2_ALG.RSA)
        self.assertIsInstance(r, TPM2_ALG)

        rp = 2 ** TPM2_ALG.RSA
        self.assertIsInstance(rp, TPM2_ALG)

        rrs = 1 >> TPM2_ALG.RSA
        self.assertIsInstance(rrs, TPM2_ALG)

        rs = TPM2_ALG.RSA >> 1
        self.assertIsInstance(rs, TPM2_ALG)

        rsub = 1 - TPM2_ALG.RSA
        self.assertIsInstance(rsub, TPM2_ALG)

        rdiv = 1 / TPM2_ALG.RSA
        self.assertIsInstance(rdiv, TPM2_ALG)

        sub = TPM2_ALG.RSA - 1
        self.assertIsInstance(sub, TPM2_ALG)

        div = TPM2_ALG.RSA / 1
        self.assertIsInstance(div, TPM2_ALG)

    def test_TPM_FRIENDLY_INT_type(self):
        self.assertIsInstance(TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS, TPMA_OBJECT)

    def test_TPM2_RC_decode(self):
        self.assertEqual(TPM2_RC.NV_LOCKED.decode(), "tpm:error(2.0): NV access locked")

    def test_TSS2_RC_decode(self):
        self.assertEqual(
            TSS2_RC.ESYS_RC_BAD_VALUE.decode(), "esapi:A parameter has a bad value"
        )

    def test_TPMT_SENSITIVE_to_pem(self):

        priv = TPMT_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        pem = priv.to_pem(pub.publicArea)
        load_pem_private_key(pem, password=None)

        # with a password
        pem = priv.to_pem(pub.publicArea, password=b"foo")
        with self.assertRaises(TypeError):
            load_pem_private_key(pem, password=None)

        load_pem_private_key(pem, password=b"foo")

    def test_TPM2B_SENSITIVE_to_pem(self):

        priv = TPM2B_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        pem = priv.to_pem(pub.publicArea)
        load_pem_private_key(pem, password=None)

        # with a password
        pem = priv.to_pem(pub.publicArea, password=b"foo")
        with self.assertRaises(TypeError):
            load_pem_private_key(pem, password=None)

        load_pem_private_key(pem, password=b"foo")

    def test_TPMT_SENSITIVE_to_der(self):

        priv = TPMT_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        der = priv.to_der(pub.publicArea)
        load_der_private_key(der, password=None)

    def test_TPM2B_SENSITIVE_to_der(self):

        priv = TPM2B_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        der = priv.to_der(pub.publicArea)
        load_der_private_key(der, password=None)

    def test_TPMT_SENSITIVE_to_ssh(self):

        priv = TPMT_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        sshpem = priv.to_ssh(pub.publicArea)
        load_ssh_private_key(sshpem, password=None)

    def test_TPM2B_SENSITIVE_to_ssh(self):

        priv = TPM2B_SENSITIVE.from_pem(rsa_parent_key)
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        sshpem = priv.to_ssh(pub.publicArea)
        load_ssh_private_key(sshpem, password=None)

    def test_TPM2B_PUBLIC_from_pem_strings(self):
        pub = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            objectAttributes="userwithauth|sign",
            scheme="rsapss",
            symmetric="aes128ecb",
        )
        self.assertEqual(
            pub.publicArea.objectAttributes,
            (TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT),
        )
        self.assertEqual(
            pub.publicArea.parameters.rsaDetail.scheme.scheme, TPM2_ALG.RSAPSS
        )
        self.assertEqual(pub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes, 128)
        self.assertEqual(
            pub.publicArea.parameters.rsaDetail.symmetric.mode.aes, TPM2_ALG.ECB
        )

    def test_struct_type_map(self):
        pub = TPMT_PUBLIC(type=TPM2_ALG.RSA)
        self.assertEqual(pub.type, TPM2_ALG.RSA)
        self.assertIsInstance(pub.type, TPM2_ALG)

        ctx = TPMS_CONTEXT(savedHandle=0x40000000)
        self.assertEqual(ctx.savedHandle, TPM2_HANDLE(0x40000000))
        self.assertIsInstance(ctx.savedHandle, TPM2_HANDLE)

    def test_list_type_map(self):
        algs = TPML_ALG((TPM2_ALG.SHA256,))
        self.assertEqual(algs[0], TPM2_ALG.SHA256)
        self.assertIsInstance(algs[0], TPM2_ALG)

        hl = TPML_HANDLE((0x40000000,))
        self.assertEqual(hl[0], TPM2_HANDLE(0x40000000))
        self.assertIsInstance(hl[0], TPM2_HANDLE)

    def test_TPMA_CC(self):
        cca = TPMA_CC.NV | 0x1234 | (5 << TPMA_CC.CHANDLES_SHIFT)
        self.assertEqual(str(cca), "nv|commandindex=0x1234|chandles=0x5")

        pcca = TPMA_CC.parse("nv|commandindex=1234|chandles=5")
        self.assertEqual(pcca & TPMA_CC.NV, TPMA_CC.NV)
        self.assertEqual(pcca.commandindex, 1234)
        self.assertEqual(pcca.chandles, 5)

        ccs = str(TPMA_CC.NV | TPMA_CC.V)
        self.assertEqual(ccs, "nv|v")


if __name__ == "__main__":
    unittest.main()
