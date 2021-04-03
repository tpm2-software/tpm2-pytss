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


if __name__ == "__main__":
    unittest.main()
