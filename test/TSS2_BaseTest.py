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
    def setUp(self):
        self.tpm = TpmSimulator.getSimulator()
        self.tpm.start()

    def tearDown(self):
        self.tpm.close()


class TSS2_EsapiTest(TSS2_BaseTest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tcti = None
        self.ectx = None

    def setUp(self):
        super().setUp()
        try:
            self.tcti = self.tpm.get_tcti()
            with ESAPI(self.tcti) as ectx:
                ectx.Startup(TPM2_SU.CLEAR)

        except Exception as e:
            self.tpm.close()
            raise e
        self.ectx = ESAPI(self.tcti)

    def tearDown(self):
        self.ectx.close()
        self.tcti.close()
        super().tearDown()


class TSS2_FapiTest(TSS2_BaseTest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fapi = None
        self.fapi_config = None

    def setUp(self):
        super().setUp()

        # This assumes that mssim or something similar is started and needs a startup command
        super().setUpClass()

        self.fapi_config = FapiConfig(
            temp_dirs=True, tcti=self.tpm.tcti_name_conf, ek_cert_less="yes"
        ).__enter__()

        try:
            with FAPI() as fapi:
                fapi.provision()
        except Exception as e:
            self.tpm.close()
            raise e

        self.fapi = FAPI()
        self.fapi.__enter__()

    def tearDown(self):
        self.fapi.__exit__(*sys.exc_info())
        self.fapi = None

        if self.fapi_config is not None:
            self.fapi_config.__exit__(*sys.exc_info())
            self.fapi_config = None

        super().tearDown()
