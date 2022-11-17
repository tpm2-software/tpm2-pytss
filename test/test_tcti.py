#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import unittest

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_EsapiTest


class MyTCTI(PyTCTI):
    def __init__(self, subtcti, magic=None):
        self._tcti = subtcti
        self._is_finalized = False
        self._error = None

        if magic is not None:
            super().__init__(magic=magic)
        else:
            super().__init__()

    @property
    def is_finalized(self):
        return self._is_finalized

    def do_transmit(self, command):
        self._tcti.transmit(command)

    def do_receive(self, timeout):
        return self._tcti.receive()

    def do_cancel(self):
        self._tcti.cancel()

    def do_get_poll_handles(self):
        return self._tcti.get_poll_handles()

    def do_set_locality(self, locality):
        self._tcti.set_locality(locality)

    def do_make_sticky(self, handle, is_sticky):
        if self._tcti is not None:
            self._tcti.make_sticky(handle, is_sticky)

        if self._error is not None:
            raise self._error

    def do_finalize(self):
        self._is_finalized = True
        if self._error is not None:
            raise self._error


class TestTCTI(TSS2_EsapiTest):
    def test_init(self):
        self.assertEqual(self.tcti.version, 2)
        self.assertGreater(int.from_bytes(self.tcti.magic, "big"), 0)

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
            self.skipTest("cancel not supported by swtpm")

        startup = b"\x80\x01\x00\x00\x00\x0C\x00\x00\x01\x44\x00\x00"
        self.tcti.transmit(startup)
        self.tcti.cancel()

    def test_get_poll_handles(self):
        tcti_name = getattr(self.tcti, "name", "")
        try:
            self.tcti.get_poll_handles()
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

    def test_custom_pytcti_esapi(self):

        t = MyTCTI(self.tcti)
        e = ESAPI(t)
        e.get_random(4)

        e.startup(TPM2_SU.CLEAR)

    def test_custom_pytcti_C_wrapper_transmit_receive(self):

        t = MyTCTI(self.tcti)

        # Go through the C API directly and call transmit and recv
        t.transmit(b"\x80\x01\x00\x00\x00\x0C\x00\x00\x01\x44\x00\x00")
        resp = t.receive(-1)
        self.assertEqual(resp, b"\x80\x01\x00\x00\x00\n\x00\x00\x01\x00")

    def test_custom_pytcti_cancel(self):
        if getattr(self.tcti, "name", "") == "swtpm":
            self.skipTest("cancel not supported by swtpm")

        t = MyTCTI(self.tcti)

        t.transmit(b"\x80\x01\x00\x00\x00\x0C\x00\x00\x01\x44\x00\x00")
        t.cancel()

    def test_custom_pytcti_finalize(self):
        t = MyTCTI(self.tcti)
        t.finalize()
        self.assertTrue(t.is_finalized)

    def test_custom_pytcti_get_poll_handles(self):
        tcti_name = getattr(self.tcti, "name", "")
        t = MyTCTI(self.tcti)
        try:
            handles = t.get_poll_handles()
            for h in handles:
                self.assertTrue(isinstance(h, PollData))
        except TSS2_Exception as e:
            if e.rc != lib.TSS2_TCTI_RC_NOT_IMPLEMENTED:
                raise e
            else:
                self.skipTest(f"get_poll_handles not supported by {tcti_name}")

    def test_custom_pytcti_set_locality(self):
        t = MyTCTI(self.tcti)
        t.set_locality(TPMA_LOCALITY.TWO)

    def test_custom_pytcti_make_sticky(self):
        t = MyTCTI(None)
        t._error = None
        t.make_sticky(0, 0)
        t.make_sticky(0, 1)
        t.make_sticky(0, False)

        # Test that throwing an exception shows the originating exception
        t._error = RuntimeError("Bills Error")
        with self.assertRaises(RuntimeError, msg="Bills Error"):
            t.make_sticky(5, True)

        t._v2 = None
        with self.assertRaises(TSS2_Exception):
            t.make_sticky(0, 0)

    def test_custom_pytcti_version(self):
        t = MyTCTI(None)
        self.assertEqual(t.version, 2)

    def test_custom_pytcti_magic(self):
        t = MyTCTI(None)
        magic = b"PYTCTI\x00\x00"
        self.assertEqual(t.magic, magic)

        # max magic len
        magic = b"THISISIT"
        t = MyTCTI(None, magic)
        self.assertEqual(t.magic, magic)

        # small magic len
        magic = b"COOL"
        t = MyTCTI(None, magic)
        self.assertEqual(t.magic, magic)

        # min magic
        magic = b""
        t = MyTCTI(None, magic)
        self.assertEqual(t.magic, magic)

        with self.assertRaises(ValueError):
            MyTCTI(None, b"THISISTOOBIG")

    def test_custom_pytcti_ctx_manager_finalize(self):
        with MyTCTI(self.tcti) as t:
            e = ESAPI(t)
            r = e.get_random(4)
            self.assertEqual(len(r), 4)
            e.startup(TPM2_SU.CLEAR)

        self.assertTrue(t.is_finalized)

    def test_custom_pytcti_finalize_error(self):

        t = MyTCTI(self.tcti)
        t._error = RuntimeError("Bills Error 2")
        with self.assertRaises(RuntimeError, msg="Bills Error 2"):
            t.finalize()


if __name__ == "__main__":
    unittest.main()
