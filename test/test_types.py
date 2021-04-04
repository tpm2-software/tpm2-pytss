#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""

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

        pcr_sels = TPML_PCR_SELECTION([first, second, third])
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


if __name__ == "__main__":
    unittest.main()
