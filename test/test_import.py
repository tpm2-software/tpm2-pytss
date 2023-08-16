#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import sys
import unittest


class mocklib:
    def __init__(self, msg):
        self.msg = msg

    @property
    def lib(self):
        raise ImportError(self.msg)


class ImportTest(unittest.TestCase):
    def test_missing_symbol(self):
        if "tpm2_pytss" in sys.modules:
            del sys.modules["tpm2_pytss"]
        sys.modules["tpm2_pytss._libtpm2_pytss"] = mocklib(
            "/tmp/tpm2_pytss/_libtpm2_pytss.abi3.so: undefined symbol: test_symbol"
        )
        with self.assertRaises(ImportError) as e:
            import tpm2_pytss
        self.assertEqual(
            e.exception.msg,
            "failed to load tpm2-tss bindigs in /tmp/tpm2_pytss/_libtpm2_pytss.abi3.so"
            + " due to missing symbol test_symbol, ensure that you are using the same"
            + " libraries the python module was built against.",
        )

    def test_other_message(self):
        if "tpm2_pytss" in sys.modules:
            del sys.modules["tpm2_pytss"]
        sys.modules["tpm2_pytss._libtpm2_pytss"] = mocklib("I am a teapot")
        with self.assertRaises(ImportError) as e:
            import tpm2_pytss
        self.assertEqual(e.exception.msg, "I am a teapot")

    def test_not_missing_symbol(self):
        if "tpm2_pytss" in sys.modules:
            del sys.modules["tpm2_pytss"]
        sys.modules["tpm2_pytss._libtpm2_pytss"] = mocklib("/bin/ls: not a: teapot")
        with self.assertRaises(ImportError) as e:
            import tpm2_pytss
        self.assertEqual(e.exception.msg, "/bin/ls: not a: teapot")
