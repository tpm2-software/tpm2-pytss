#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""

import os
import sys
import subprocess
import unittest
from time import sleep

from tpm2_pytss.pyesys import *


class Tpm(object):
    def __init__(self):
        print("Setting up simulator: ", end="")
        self.tpm = subprocess.Popen(["tpm_server", "-rm"])
        sleep(2)
        if self.tpm.poll() is not None:
            print("tpm_server not started, retrying...")
            sleep(5)
            self.tpm = subprocess.Popen(["tpm_server"])
            sleep(2)
        if self.tpm.poll() is not None:
            print("tpm_server not started, SKIPPING")
            exit(77)  # Skipped
        print("OK")

    def close(self):
        self.tpm.terminate()
        os.unlink("NVChip")


class TestPyEsys(unittest.TestCase):
    tpm = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        TestPyEsys.tpm = Tpm()
        with EsysContext() as ectx:
            ectx.Startup(TPM2_SU.CLEAR)

    def setUp(self):
        self.ectx = EsysContext()

    def tearDown(self):
        self.ectx.close()
        self.ectx = None

    @classmethod
    def tearDownClass(cls):
        TestPyEsys.tpm.close()

    def testGetRandom(self):
        sys.stderr.write("PYTEST BILL GETRANDOM: {}\n".format(self.ectx))
        r = self.ectx.GetRandom(5)
        self.assertEqual(len(r), 5)

    def testCreatePrimary(self):
        sys.stderr.write("PYTEST BILL CREATEPRIMARY: {}".format(self.ectx))
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
