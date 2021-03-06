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
import sys
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

    @property
    def tcti_name_conf(self):
        if self._port is None:
            return None

        return f"swtpm:port={self._port}"

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

    @property
    def tcti_name_conf(self):
        if self._port is None:
            return None

        return f"mssim:port={self._port}"

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


class TSS2_BaseTest(unittest.TestCase):
    tpm = None
    tcti = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        TSS2_BaseTest.tpm = TpmSimulator.getSimulator()
        TSS2_BaseTest.tpm.start()

    @classmethod
    def tearDownClass(cls):
        TSS2_BaseTest.tpm.close()
        TSS2_BaseTest.tcti.close()


class TSS2_BaseTest(unittest.TestCase):
    tpm = None
    tcti = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        TSS2_BaseTest.tpm = TpmSimulator.getSimulator()
        TSS2_BaseTest.tpm.start()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @classmethod
    def tearDownClass(cls):
        TSS2_BaseTest.tpm.close()


class TSS2_EsapiTest(TSS2_BaseTest):
    tcti = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        super().setUpClass()
        try:
            TSS2_EsapiTest.tcti = TSS2_BaseTest.tpm.get_tcti()
            with ESAPI(TSS2_EsapiTest.tcti) as ectx:
                ectx.Startup(TPM2_SU.CLEAR)

        except Exception as e:
            TSS2_BaseTest.tpm.close()
            raise e

    def setUp(self):
        super().setUp()
        self.ectx = ESAPI(TSS2_EsapiTest.tcti)

    def tearDown(self):
        self.ectx.close()
        self.ectx = None

    @classmethod
    def tearDownClass(cls):
        TSS2_EsapiTest.tcti.close()


class TSS2_FapiTest(TSS2_BaseTest):
    fapi_config = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fapi = None

    @classmethod
    def setUpClass(cls):
        # This assumes that mssim or something similar is started and needs a startup command
        super().setUpClass()

        cls.fapi_config = FapiConfig(
            temp_dirs=True, tcti=TSS2_BaseTest.tpm.tcti_name_conf
        ).__enter__()

        try:
            with FAPI() as fapi:
                fapi.provision()
        except Exception as e:
            TSS2_BaseTest.tpm.close()
            raise e

    def setUp(self):
        super().setUp()
        self.fapi = FAPI()
        self.fapi.__enter__()

    def tearDown(self):
        self.fapi.__exit__(*sys.exc_info())
        self.fapi = None

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

        if cls.fapi_config is not None:
            cls.fapi_config.__exit__(*sys.exc_info())
            cls.fapi_config = None
