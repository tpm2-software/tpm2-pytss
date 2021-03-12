#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""

import pytest

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_FapiTest


@pytest.mark.forked
class TestFapi(TSS2_FapiTest):
    def testProvision(self):
        r = self.fapi.provision()
        self.assertEqual(r, False)

    def testGetRandom(self):
        r = self.fapi.get_random(42)
        self.assertEqual(len(r), 42)


if __name__ == "__main__":
    unittest.main()
