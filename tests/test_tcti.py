import unittest

from tpm2_pytss.tcti import TCTI
from tpm2_pytss.util.simulator import SimulatorTest


class TestTCTI(unittest.TestCase):
    def test_load(self):
        name = "mssim"
        tcti = TCTI.load(name)
        with self.subTest(check_name=1):
            self.assertEqual(tcti.NAME, name)
            self.assertEqual(tcti.CONTEXT.NAME, name)
            self.assertEqual(tcti.__class__.__qualname__, name.title() + "TCTI")
            self.assertEqual(tcti.CONTEXT.__qualname__, name.title() + "TCTIContext")


class TestTCTIContext(SimulatorTest, unittest.TestCase):
    def test_create_context(self):
        tcti = TCTI.load("mssim")
        with tcti(f"port={self.simulator.port}") as ctx:
            pass
