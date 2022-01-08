#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import os
import sys
import unittest
import subprocess
from textwrap import dedent
from .TSS2_BaseTest import TSS2_BaseTest
from tpm2_pytss.ESAPI import ESAPI
from tpm2_pytss.constants import TPM2_SU, TPM2_ALG, TPMA_NV
from tpm2_pytss.types import TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC


class ExamplesTest(TSS2_BaseTest):
    def setUp(self):
        super().setUp()
        with ESAPI(self.tpm.tcti_name_conf) as ectx:
            ectx.startup(TPM2_SU.CLEAR)

    def test_tpm2_filternv(self):
        if sys.version_info < (3, 7):
            self.skipTest("missing arguments to subprocess.run in 3.6")
        expected = dedent(
            """
        0x1000000:
          name: 0004b94c956b5b834eed31a3b5d07487cb287f245db5
          hash algorithm:
            friendly: sha
            value: 0x4
          attributes:
            friendly: authwrite|authread
            value: 0x40004
          size: 1

        0x1000002:
          name: 000bbcd32f1a6dd2c59a9cce18cd1c936a5def094aead7c7a5f4a8eef3ef0ee5ca78
          hash algorithm:
            friendly: sha256
            value: 0xb
          attributes:
            friendly: policywrite|ownerread
            value: 0x20008
          size: 2
          authorization policy: 1212121212121212121212121212121212121212121212121212121212121212

        """
        ).lstrip()
        expected_filtered = dedent(
            """
        0x1000002:
          name: 000bbcd32f1a6dd2c59a9cce18cd1c936a5def094aead7c7a5f4a8eef3ef0ee5ca78
          hash algorithm:
            friendly: sha256
            value: 0xb
          attributes:
            friendly: policywrite|ownerread
            value: 0x20008
          size: 2
          authorization policy: 1212121212121212121212121212121212121212121212121212121212121212

        """
        ).lstrip()

        with ESAPI(self.tpm.tcti_name_conf) as ectx:
            nvpub1 = TPM2B_NV_PUBLIC(
                nvPublic=TPMS_NV_PUBLIC(
                    nvIndex=0x01000000,
                    nameAlg=TPM2_ALG.SHA1,
                    attributes=TPMA_NV.AUTHREAD | TPMA_NV.AUTHWRITE,
                    dataSize=1,
                )
            )
            ectx.nv_define_space(None, nvpub1)
            nvpub2 = TPM2B_NV_PUBLIC(
                nvPublic=TPMS_NV_PUBLIC(
                    nvIndex=0x01000002,
                    nameAlg=TPM2_ALG.SHA256,
                    attributes=TPMA_NV.POLICYWRITE | TPMA_NV.OWNERREAD,
                    authPolicy=b"\x12" * 32,
                    dataSize=2,
                )
            )
            ectx.nv_define_space(None, nvpub2)

        res = subprocess.run(
            (
                "python3",
                "./examples/tpm2_filternv/tpm2_filternv",
                "--tcti",
                self.tpm.tcti_name_conf,
            ),
            timeout=20,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.stderr, "")
        self.assertEqual(res.stdout, expected)
        self.assertEqual(res.returncode, 0)

        res = subprocess.run(
            (
                "python3",
                "./examples/tpm2_filternv/tpm2_filternv",
                "--tcti",
                self.tpm.tcti_name_conf,
                "--filter",
                "ownerread",
            ),
            timeout=20,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.stderr, "")
        self.assertEqual(res.stdout, expected_filtered)
        self.assertEqual(res.returncode, 0)
