#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import unittest

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_EsapiTest


class TestTCTI(TSS2_EsapiTest):
    def test_init(self):
        self.assertEqual(self.tcti.version, 2)
        self.assertGreater(self.tcti.magic, 0)

        v1ctx = ffi.cast("TSS2_TCTI_CONTEXT_COMMON_V1 *", self.tcti._ctx)
        v1ctx.version = 1

        tcti = TCTI(self.tcti._ctx)
        self.assertEqual(tcti.version, 1)
        self.assertEqual(tcti._v2, None)

    def test_transmit_receive(self):
        startup = b"\x80\x01\x00\x00\x00\x0C\x00\x00\x01\x44\x00\x00"
        self.tcti.transmit(startup)

        resp = self.tcti.receive()
        self.assertEqual(resp, b"\x80\x01\x00\x00\x00\n\x00\x00\x01\x00")

    def test_finalize(self):
        tcti = TCTI(self.tcti._ctx)
        tcti.finalize()

    def test_cancel(self):
        if getattr(self.tcti, "name", "") == "swtpm":
            self.skipTest("cancel supported by swtpm")

        startup = b"\x80\x01\x00\x00\x00\x0C\x00\x00\x01\x44\x00\x00"
        self.tcti.transmit(startup)
        self.tcti.cancel()

    def test_get_poll_handles(self):
        tcti_name = getattr(self.tcti, "name", "")
        try:
            handles = self.tcti.get_poll_handles()
        except TSS2_Exception as e:
            if e.rc != lib.TSS2_TCTI_RC_NOT_IMPLEMENTED:
                raise e
            else:
                self.skipTest(f"get_poll_handles not supported by {tcti_name}")

    def test_set_locality(self):
        self.tcti.set_locality(TPMA_LOCALITY.TWO)

    def test_make_sticky(self):
        tcti_name = getattr(self.tcti, "name", "")
        if tcti_name in ("swtpm", "mssim"):
            self.skipTest(f"make_sticky not supported by {tcti_name}")
        raise Exception(self.tcti.name)
        self.tcti.make_sticky(0, 0)

        tcti._v2 = None
        with self.assertRaises(RuntimeError) as e:
            self.tcti.make_sticky(0, 0)
        self.assertEqual(str(e.exception), "unsupported by TCTI API version")

    def test_tctildr(self):
        self.assertIsInstance(self.tcti.name, str)
        self.assertIsInstance(self.tcti.conf, str)

        with self.assertRaises(TypeError):
            TCTILdr(name=None, conf=1234)

        with self.assertRaises(TypeError):
            TCTILdr(name=1234, conf=None)


if __name__ == "__main__":
    unittest.main()
