# SPDX-License-Identifier: BSD-2

import shutil
import logging
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import cdll


from tpm2_pytss import *


class BaseTpmSimulator(object):
    def __init__(self):
        self.tpm = None
        self._port = None

    @staticmethod
    def ready(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("localhost", port)) == 0

    def start(self):
        logger = logging.getLogger("DEBUG")
        logger.debug('Setting up simulator: "{}"'.format(self.exe))

        tpm = None
        for _ in range(0, 20):

            random_port = random.randrange(2321, 65534)

            sim = self._start(port=random_port)
            for _ in range(0, 10):
                rc = sim.poll()
                if rc is not None:
                    logger.debug(f"Simulator {self.exe} exited with {rc}")
                    break
                if (
                    sim.poll() is None
                    and self.ready(random_port)
                    and self.ready(random_port + 1)
                ):
                    tpm = sim
                    break
                time.sleep(0.1)

            if tpm:
                self.tpm = sim
                self._port = random_port
                logger.debug(f"started {self.exe} on port {random_port}\n")
                break
            else:
                sim.kill()

        if not tpm:
            raise SystemError("Could not start simulator")

    def close(self):
        if self.tpm.poll() is not None:
            return
        self.tpm.terminate()
        try:
            self.tpm.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.tpm.kill()
        self.tpm.wait(timeout=10)

    def __str__(self):
        return self.exe


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
        return tpm

    @property
    def tcti_name_conf(self):
        if self._port is None:
            return None

        return f"swtpm:port={self._port}"

    def get_tcti(self):
        if self._port is None:
            return None

        return TCTILdr("swtpm", f"port={self._port}")


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
            return tpm

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

        return TCTILdr("mssim", f"port={self._port}")


class TpmSimulator(object):

    SIMULATORS = [
        SwtpmSimulator,
        IBMSimulator,
    ]

    @staticmethod
    def getSimulator():

        for sim in TpmSimulator.SIMULATORS:
            exe = shutil.which(sim.exe)
            if not exe:
                print(f'Could not find executable: "{sim.exe}"', file=sys.stderr)
                continue
            try:
                cdll.LoadLibrary(sim.libname)
            except OSError as e:
                print(
                    f'Could not load libraries: "{sim.exe}", error: {e}',
                    file=sys.stderr,
                )
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

    def skipIfAlgNotSupported(self, alg: TPM2_ALG):
        self.skipTest(f'Algorithm "{alg}" not supported by simulator')

    def setUp(self):
        super().setUp()
        try:
            # use str initializer here to test string inputs to ESAPI constructor
            with ESAPI(self.tpm.tcti_name_conf) as ectx:
                ectx.startup(TPM2_SU.CLEAR)

        except Exception as e:
            self.tpm.close()
            raise e
        self.tcti = self.tpm.get_tcti()
        self.ectx = ESAPI(self.tcti)

        # record the supported algorithms
        self._supported_algs = []
        more = True
        while more:
            more, data = self.ectx.get_capability(
                TPM2_CAP.ALGS, 0, lib.TPM2_MAX_CAP_ALGS
            )
            self._supported_algs += [x.alg for x in data.data.algorithms]

    def tearDown(self):
        self.ectx.close()
        self.tcti.close()
        super().tearDown()
