#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""

from distutils import spawn
import logging
import os
import random
import subprocess
import tempfile
import unittest
from time import sleep
from ctypes import cdll


from tpm2_pytss import *


class BaseTpmSimulator(object):
    def __init__(self):
        self.tpm = None

    def start(self):
        logger = logging.getLogger("DEBUG")
        logger.debug('Setting up simulator: "{}"'.format(self.tpm))

        tpm = None
        for _ in range(0, 10):

            random_port = random.randrange(2321, 65534)

            tpm = self._start(port=random_port)
            if tpm:
                self.tpm = tpm
                break

        if not tpm:
            raise SystemError("Could not start simulator")

    def close(self):
        self.tpm.terminate()


class SwtpmSimulator(BaseTpmSimulator):
    exe = "swtpm"
    libname = "libtss2-tcti-swtpm.so"

    def __init__(self):
        self._port = None
        super().__init__()
        self.working_dir = tempfile.TemporaryDirectory()

    def _start(self, port):

        cmd = [
            "swtpm",
            "socket",
            "--tpm2",
            "--server",
            "port={}".format(port),
            "--ctrl",
            "type=tcp,port={}".format(port + 1),
            "--flags",
            "not-need-init",
            "--tpmstate",
            "dir={}".format(self.working_dir.name),
        ]

        tpm = subprocess.Popen(cmd)
        sleep(2)

        if not tpm.poll():
            self._port = port
            return tpm

        return None

    def get_tcti(self):
        if self._port is None:
            return None

        return TctiLdr("swtpm", f"port={self._port}")


class IBMSimulator(BaseTpmSimulator):
    exe = "tpm_server"
    libname = "libtss2-tcti-mssim.so"

    def __init__(self):
        self._port = None
        super().__init__()
        self.working_dir = tempfile.TemporaryDirectory()

    def _start(self, port):

        cwd = os.getcwd()
        os.chdir(self.working_dir.name)
        try:
            cmd = ["tpm_server", "-rm", "-port", "{}".format(port)]
            tpm = subprocess.Popen(cmd)
            sleep(2)

            if not tpm.poll():
                self._port = port
                return tpm

            return None

        finally:
            os.chdir(cwd)

    def get_tcti(self):
        if self._port is None:
            return None

        return TctiLdr("mssim", f"port={self._port}")


class TpmSimulator(object):

    SIMULATORS = [
        SwtpmSimulator,
        IBMSimulator,
    ]

    @staticmethod
    def getSimulator():

        for sim in TpmSimulator.SIMULATORS:
            exe = spawn.find_executable(sim.exe)
            if not exe:
                continue
            try:
                cdll.LoadLibrary(sim.libname)
            except OSError:
                continue

            return sim()

        raise RuntimeError(
            "Expected to find a TPM 2.0 Simulator, tried {}, got None".format(
                TpmSimulator.SIMULATORS
            )
        )


class TestPyEsys(unittest.TestCase):
    tpm = None
    tcti = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        TestPyEsys.tpm = TpmSimulator.getSimulator()
        TestPyEsys.tpm.start()
        try:
            TestPyEsys.tcti = TestPyEsys.tpm.get_tcti()
            with ESAPI(TestPyEsys.tcti) as ectx:
                ectx.Startup(TPM2_SU.CLEAR)

        except Exception as e:
            TestPyEsys.tpm.close()
            raise e

    def setUp(self):
        self.ectx = ESAPI(TestPyEsys.tcti)

    def tearDown(self):
        self.ectx.close()
        self.ectx = None

    @classmethod
    def tearDownClass(cls):
        TestPyEsys.tpm.close()
        TestPyEsys.tcti.close()

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
