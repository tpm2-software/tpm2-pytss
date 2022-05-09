#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2
import unittest
from packaging.version import Version, InvalidVersion

from tpm2_pytss.internal.utils import _lib_version_normalize


class InternalTest(unittest.TestCase):
    def test_lib_version_normalize(self):

        v = _lib_version_normalize("3.1.0-126-g0fd1c5fbbaf2")
        self.assertEqual(v, Version("3.1.0.dev126"))

        v = _lib_version_normalize("3.1.0-126-g0fd1c5fbbaf2-dirty")
        self.assertEqual(v, Version("3.1.0a126.dev126"))

        v = _lib_version_normalize("1.1.0-rc0")
        self.assertEqual(v, Version("1.1.0rc0"))

        v = _lib_version_normalize("1.1.0")
        self.assertEqual(v, Version("1.1.0"))

        with self.assertRaises(InvalidVersion):
            _lib_version_normalize("3.1.0-126-g0fd1c5fbbaf2-dirty-bad")


if __name__ == "__main__":
    unittest.main()
