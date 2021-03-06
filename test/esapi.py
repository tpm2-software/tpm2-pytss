#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""

import unittest

from tpm2_pytss import *
from TSS2_BaseTest import TSS2_EsapiTest


class TestEsys(TSS2_EsapiTest):
    def testGetRandom(self):
        r = self.ectx.GetRandom(5)
        self.assertEqual(len(r), 5)

    def testCreatePrimary(self):
        inSensitive = TPM2B_SENSITIVE_CREATE()
        inPublic = TPM2B_PUBLIC()
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

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

        self.ectx.setAuth(ESYS_TR.OWNER, "")

        x, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER,
            inSensitive,
            inPublic,
            outsideInfo,
            creationPCR,
            session1=ESYS_TR.PASSWORD,
        )
        self.assertIsNot(x, None)


if __name__ == "__main__":
    unittest.main()
