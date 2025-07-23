#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2
import unittest

from tpm2_pytss.internal.utils import TSS2Version


class InternalTest(unittest.TestCase):
    def test_lib_version_strings(self):

        versions = []

        # try the variants with a single major number
        versions.append(TSS2Version("1-rc0"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_00000000_00000000_00
        )

        versions.append(TSS2Version("1-rc0-dirty"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_00000000_00000000_01
        )

        versions.append(TSS2Version("1-rc0-2-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_00000000_00000002_00
        )

        versions.append(TSS2Version("1-rc0-2-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_00000000_00000002_01
        )

        versions.append(TSS2Version("1"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_FFFFFFFF_00000000_00
        )

        versions.append(TSS2Version("1-5-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_FFFFFFFF_00000005_00
        )

        versions.append(TSS2Version("1-5-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000001_00000000_00000000_FFFFFFFF_00000005_01
        )

        # try major minor variants
        versions.append(TSS2Version("2.0-rc0"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_00000000_00000000_00
        )

        versions.append(TSS2Version("2.0-rc0-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_00000000_00000000_01
        )

        versions.append(TSS2Version("2.0-rc0-2-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_00000000_00000002_00
        )

        versions.append(TSS2Version("2.0-rc0-2-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_00000000_00000002_01
        )

        versions.append(TSS2Version("2.0"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_FFFFFFFF_00000000_00
        )

        versions.append(TSS2Version("2.0-5-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_FFFFFFFF_00000005_00
        )

        versions.append(TSS2Version("2.0-5-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000000_FFFFFFFF_00000005_01
        )

        # try major minor patch variants
        versions.append(TSS2Version("2.0.1-rc0"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_00000000_00000000_00
        )

        versions.append(TSS2Version("2.0.1-rc0-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_00000000_00000000_01
        )

        versions.append(TSS2Version("2.0.1-rc0-2-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_00000000_00000002_00
        )

        versions.append(TSS2Version("2.0.1-rc0-2-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_00000000_00000002_01
        )

        versions.append(TSS2Version("2.0.1"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_FFFFFFFF_00000000_00
        )

        versions.append(TSS2Version("2.0.1-5-g0fd1c5fbbaf2"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_FFFFFFFF_00000005_00
        )

        versions.append(TSS2Version("2.0.1-5-g0fd1c5fbbaf2-dirty"))
        self.assertEqual(
            versions[-1], 0x00000002_00000000_00000001_FFFFFFFF_00000005_01
        )

        # We carefully built this list in sorted order so everything should be ascending
        # in value or precedence related to index. It value at index 5 is greater than
        # the value at index 2
        v0 = versions[0]
        for v1 in versions[1:]:
            self.assertTrue(v0 < v1, f"{str(v0)} not less than {str(v1)}")
            v0 = v1

        with self.assertRaises(ValueError, msg='Invalid version string, got: "1.N.0"'):
            TSS2Version("1.N.0")

        with self.assertRaises(ValueError, msg='Invalid version string, got: "N.1.0"'):
            TSS2Version("N.1.0")

        with self.assertRaises(ValueError, msg='Invalid version string, got: "3.1.N"'):
            TSS2Version("3.1.N")

        with self.assertRaises(
            ValueError, msg='Invalid version string, got: "3.1.0-N-g0fd1c5fbbaf2-dirty"'
        ):
            TSS2Version("3.1.0-N-g0fd1c5fbbaf2-dirty")

        with self.assertRaises(
            ValueError, msg='Invalid version string, got: "3.1.0-126-g0fd1c5fbbaf2-bad"'
        ):
            TSS2Version("3.1.0-126-g0fd1c5fbbaf2-bad")


if __name__ == "__main__":
    unittest.main()
