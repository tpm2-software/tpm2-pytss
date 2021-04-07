#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""
import itertools
import unittest

from tpm2_pytss import *


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

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("+")

    def test_TPML_PCR_SELECTION_parse_plus_multiple(self):

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("+++")

    def test_TPML_PCR_SELECTION_parse_plus_unbalanced(self):

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("sha256:1+")

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("+sha256:1")

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("+sha256:1+")

    def test_TPML_PCR_SELECTION_parse_gibberish(self):

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("gibberish value")

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("foo+")

        with self.assertRaises(RuntimeError):
            TPML_PCR_SELECTION.parse("+bar")

        with self.assertRaises(RuntimeError):
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

    def test_TPMS_PCR_SELECTION_parse(self):

        x = TPMS_PCR_SELECTION.parse("sha512:1, 7, 8, 12, 18, 24")
        self.assertEqual(x.hash, TPM2_ALG.SHA512)
        self.assertEqual(x.sizeofSelect, 3)

        self.assertEqual(x.pcrSelect[0], (1 << 1 | 1 << 7))
        self.assertEqual(x.pcrSelect[1], (1 << 0 | 1 << 4))
        self.assertEqual(x.pcrSelect[2], (1 << 2))
        self.assertEqual(x.pcrSelect[3], (1 << 0))

    def test_TPMS_PCR_SELECTION_parse_None(self):

        x = TPMS_PCR_SELECTION.parse(None)
        self.assertEqual(x.hash, 0)
        self.assertEqual(x.sizeofSelect, 0)
        self.assertEqual(x.pcrSelect[0], 0)
        self.assertEqual(x.pcrSelect[1], 0)
        self.assertEqual(x.pcrSelect[2], 0)
        self.assertEqual(x.pcrSelect[3], 0)

    def test_TPMS_PCR_SELECTION_parse_empty(self):

        x = TPMS_PCR_SELECTION.parse("")
        self.assertEqual(x.hash, 0)
        self.assertEqual(x.sizeofSelect, 0)
        self.assertEqual(x.pcrSelect[0], 0)
        self.assertEqual(x.pcrSelect[1], 0)
        self.assertEqual(x.pcrSelect[2], 0)
        self.assertEqual(x.pcrSelect[3], 0)

    def test_TPMS_PCR_SELECTION_parse_out_of_bounds_pcr(self):

        with self.assertRaises(RuntimeError):
            TPMS_PCR_SELECTION.parse("sha256:42")

    def test_TPMS_PCR_SELECTION_parse_malformed(self):

        with self.assertRaises(RuntimeError):
            TPMS_PCR_SELECTION.parse("this is gibberish")

    def test_TPMS_PCR_SELECTION_parse_only_colon(self):

        with self.assertRaises(RuntimeError):
            TPMS_PCR_SELECTION.parse(":")

    def test_TPMS_PCR_SELECTION_parse_only_bank_and_colon(self):

        with self.assertRaises(RuntimeError):
            TPMS_PCR_SELECTION.parse("sha256:")

    def test_TPMS_PCR_SELECTION_parse_bank_and_garbage(self):

        with self.assertRaises(RuntimeError):
            TPMS_PCR_SELECTION.parse("sha256:foo")

    def test_TPMS_PCR_SELECTION_parse_multiple_colons(self):

        with self.assertRaises(RuntimeError):
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
        digest = TPM2B_DIGEST(size=4, buffer=b"test")

        self.assertEqual(digest.size, 4)
        b = ffi.buffer(digest.buffer, digest.size)
        self.assertEqual(b, b"test")

        with self.assertRaises(
            AttributeError, msg="TPM2B_DIGEST has no field by the name of badfield"
        ):
            TPM2B_DIGEST(badfield=1)

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

        with self.assertRaises(RuntimeError):
            TPM2_ALG.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_ALG.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_ALG.parse("foo")

    def test_ESYS_TR(self):
        self.assertEqual(ESYS_TR.parse("PCR0"), ESYS_TR.PCR0)
        self.assertEqual(ESYS_TR.parse("NONE"), ESYS_TR.NONE)
        self.assertEqual(ESYS_TR.parse("LoCkout"), ESYS_TR.LOCKOUT)
        self.assertEqual(ESYS_TR.parse("owner"), ESYS_TR.OWNER)
        self.assertEqual(ESYS_TR.parse("NuLL"), ESYS_TR.NULL)

        with self.assertRaises(RuntimeError):
            ESYS_TR.parse("")

        with self.assertRaises(RuntimeError):
            ESYS_TR.parse(None)

        with self.assertRaises(RuntimeError):
            ESYS_TR.parse("foo"), TPM2_ALG.SHA512

    def test_TPM2_ECC(self):
        self.assertEqual(TPM2_ECC.parse("NONE"), TPM2_ECC.NONE)
        self.assertEqual(TPM2_ECC.parse("nist_p192"), TPM2_ECC.NIST_P192)
        self.assertEqual(TPM2_ECC.parse("BN_P256"), TPM2_ECC.BN_P256)
        self.assertEqual(TPM2_ECC.parse("sm2_P256"), TPM2_ECC.SM2_P256)

        with self.assertRaises(RuntimeError):
            TPM2_ECC.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_ECC.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_ECC.parse("foo")

    def test_TPM2_CC(self):
        self.assertEqual(TPM2_CC.parse("NV_Increment"), TPM2_CC.NV_Increment)
        self.assertEqual(TPM2_CC.parse("PCR_Reset"), TPM2_CC.PCR_Reset)
        self.assertEqual(TPM2_CC.parse("Certify"), TPM2_CC.Certify)
        self.assertEqual(TPM2_CC.parse("UnSEAL"), TPM2_CC.Unseal)

        with self.assertRaises(RuntimeError):
            TPM2_CC.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_CC.parse(None)

        with self.assertRaises(RuntimeError):
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

        with self.assertRaises(RuntimeError):
            TPMA_OBJECT.parse("")

        with self.assertRaises(RuntimeError):
            TPMA_OBJECT.parse(None)

        with self.assertRaises(RuntimeError):
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

        with self.assertRaises(RuntimeError):
            TPMA_NV.parse("")

        with self.assertRaises(RuntimeError):
            TPMA_NV.parse(None)

        with self.assertRaises(RuntimeError):
            TPMA_NV.parse("foo")

    def test_TPM2_SPEC(self):
        self.assertEqual(TPM2_SPEC.parse("Family"), TPM2_SPEC.FAMILY)
        self.assertEqual(TPM2_SPEC.parse("Level"), TPM2_SPEC.LEVEL)
        self.assertEqual(TPM2_SPEC.parse("DAY_of_YEAR"), TPM2_SPEC.DAY_OF_YEAR)

        with self.assertRaises(RuntimeError):
            TPM2_SPEC.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_SPEC.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_SPEC.parse("foo")

    def test_TPM2_GENERATED_VALUE(self):
        self.assertEqual(
            TPM2_GENERATED_VALUE.parse("value"), TPM2_GENERATED_VALUE.VALUE
        )

        with self.assertRaises(RuntimeError):
            TPM2_GENERATED_VALUE.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_GENERATED_VALUE.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_GENERATED_VALUE.parse("foo")

    def test_TPM2_RC(self):
        self.assertEqual(TPM2_RC.parse("Success"), TPM2_RC.SUCCESS)
        self.assertEqual(TPM2_RC.parse("HMAC"), TPM2_RC.HMAC)
        self.assertEqual(TPM2_RC.parse("NO_RESULT"), TPM2_RC.NO_RESULT)

        with self.assertRaises(RuntimeError):
            TPM2_RC.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_RC.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_RC.parse("foo")

    def test_TPM2_EO(self):
        self.assertEqual(TPM2_EO.parse("EQ"), TPM2_EO.EQ)
        self.assertEqual(TPM2_EO.parse("unsigned_GT"), TPM2_EO.UNSIGNED_GT)
        self.assertEqual(TPM2_EO.parse("BITCLEAR"), TPM2_EO.BITCLEAR)

        with self.assertRaises(RuntimeError):
            TPM2_EO.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_EO.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_EO.parse("foo")

    def test_TPM2_ST(self):
        self.assertEqual(TPM2_ST.parse("null"), TPM2_ST.NULL)
        self.assertEqual(TPM2_ST.parse("AUTH_SECRET"), TPM2_ST.AUTH_SECRET)
        self.assertEqual(TPM2_ST.parse("fu_manifest"), TPM2_ST.FU_MANIFEST)

        with self.assertRaises(RuntimeError):
            TPM2_ST.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_ST.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_ST.parse("foo")

    def test_TPM2_SU(self):
        self.assertEqual(TPM2_SU.parse("clear"), TPM2_SU.CLEAR)
        self.assertEqual(TPM2_SU.parse("State"), TPM2_SU.STATE)

        with self.assertRaises(RuntimeError):
            TPM2_SU.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_SU.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_SU.parse("foo")

    def test_TPM2_SE(self):
        self.assertEqual(TPM2_SE.parse("hmac"), TPM2_SE.HMAC)
        self.assertEqual(TPM2_SE.parse("TRiaL"), TPM2_SE.TRIAL)
        self.assertEqual(TPM2_SE.parse("POLICY"), TPM2_SE.POLICY)

        with self.assertRaises(RuntimeError):
            TPM2_SE.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_SE.parse(None)

        with self.assertRaises(RuntimeError):
            TPM2_SE.parse("foo")

    def test_TPM2_PT(self):
        self.assertEqual(TPM2_PT.parse("none"), TPM2_PT.NONE)
        self.assertEqual(TPM2_PT.parse("GrouP"), TPM2_PT.GROUP)
        self.assertEqual(TPM2_PT.parse("FIXED"), TPM2_PT.FIXED)

        with self.assertRaises(RuntimeError):
            TPM2_PT.parse("")

        with self.assertRaises(RuntimeError):
            TPM2_PT.parse(None)

        with self.assertRaises(RuntimeError):
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
        pb.publicArea.authPolicy.size = 8
        pb.publicArea.authPolicy.buffer = b"password"
        b = pb.publicArea.authPolicy.Marshal()
        self.assertEqual(b, b"\x00\x08password")

    def test_unmarshal(self):
        buf = b"\x00\x05test1"
        d, offset = TPM2B_DIGEST.Unmarshal(buf)
        self.assertEqual(offset, 7)
        self.assertEqual(d.size, 5)
        db = ffi.buffer(d.buffer, d.size)
        self.assertEqual(db, b"test1")

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
            f"ecc:ecdh-sha384",
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

    def test_TPML_ALG_parse_none(self):
        a = TPML_ALG.parse(None)
        self.assertEqual(len(a), 0)

    def test_TPML_ALG_parse_empty(self):
        a = TPML_ALG.parse("")
        self.assertEqual(len(a), 0)

    def test_TPML_ALG_parse_commas(self):
        a = TPML_ALG.parse(",,,,,,")
        self.assertEqual(len(a), 0)

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

        with self.assertRaises(RuntimeError):
            TPML_ALG.parse("not,real,alg")

        with self.assertRaises(RuntimeError):
            TPML_ALG.parse("jfghsjhdgfdhg")

        with self.assertRaises(RuntimeError):
            TPML_ALG.parse("aes,rsa,foo")


if __name__ == "__main__":
    unittest.main()
