#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import os
import unittest

from tpm2_pytss.utils import *


class TypesTest(unittest.TestCase):
    def test_get_logging(self):
        if "TSS2_LOG" in os.environ:
            del os.environ["TSS2_LOG"]
        curlog = get_logging()
        self.assertEqual(len(curlog), 0)

        os.environ["TSS2_LOG"] = "all+NONE,TCTI+trace"
        curlog = get_logging()
        self.assertEqual(len(curlog), 2)
        self.assertEqual(curlog["all"], "none")
        self.assertEqual(curlog["tcti"], "trace")

        os.environ["TSS2_LOG"] = "all-none"
        curlog = get_logging()
        self.assertEqual(len(curlog), 0)

    def test_set_logging(self):
        if "TSS2_LOG" in os.environ:
            del os.environ["TSS2_LOG"]

        set_logging(marshal="traCe")
        self.assertEqual(os.environ["TSS2_LOG"], "marshal+trace")

        set_logging(sys="ERROR")
        self.assertEqual(os.environ["TSS2_LOG"], "marshal+trace,sys+error")

        set_logging(marshal=None)
        self.assertEqual(os.environ["TSS2_LOG"], "sys+error")

        with self.assertRaises(ValueError) as e:
            set_logging(madeup="debug")
        self.assertEqual(str(e.exception), "unknown logging module: madeup")

        with self.assertRaises(ValueError) as e:
            set_logging(fapi="madeup")
        self.assertEqual(str(e.exception), "unknown logging level: madeup")
