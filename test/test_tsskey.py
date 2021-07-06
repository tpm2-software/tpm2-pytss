#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
"""
import binascii
import itertools
import unittest

from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey, parent_rsa_template, parent_ecc_template
from .TSS2_BaseTest import TSS2_EsapiTest


rsa_pem = b"""-----BEGIN TSS2 PRIVATE KEY-----
MIIB8gYGZ4EFCgEDoAMBAQECBEAAAAEEggEYARYAAQALAAYEcgAAABAAEAgAAAEA
AQEAzF/VFhLaIJ9Y3up8slssYhV1Fhh7KwYBCR1dqLeI9QkDF6M05b/Uc589yMsn
WVIheHnkEEXyo+rD6q12BpDrC9nS6G11hd9e5TPAibVOAvt8jY3C6/b0JGCFpMNq
W69ZonwSPO+aMPXogRBk2OL/jeost9IFbcJjEkwIs5rcaF4sI8wOXTXAx8rrqp0B
aUjbZz1OJl9PxyCtizLPtdzfCoHVVu9FDrncKpSV1GuGWV6QCTAi8ln1KnRUdmnF
YBltollhuZ5CLQRekfDdiPkm9ez2Ii/sbes2UvX3vSbyrI1WWCoNqeanSMDSvuMF
CEBd8i5YDXhAYLcSu/shWZlvPQSBwAC+ACBvkTiYshUXeUbh6Sp+9uSw1RsgGNSf
3BrApTSK5XtGEAAQUjLH4kLMJSC2c2KXRW/H9o9tuhafEX3VwlutMcz3AW+3m/gq
MHGtezT22Oy+jImy2n1NiFotqF/3xZr6WD9IrrJh9MKhWZfucOgCpTclo7P3OaAX
pCz81gA+sZ1NvvOLHL/ULNcKPcltDOHmI1ag6rhz1vQIq3r7Wd71RI5a/gUGxPCx
RmxDJYOlsFlR3mG/MiqSSB6dZ67H/Q==
-----END TSS2 PRIVATE KEY-----
"""


class TSSKeyTest(TSS2_EsapiTest):
    def test_rsa_frompem(self):
        key = TSSPrivKey.fromPEM(rsa_pem)

    def test_rsa_topem(self):
        key = TSSPrivKey.fromPEM(rsa_pem)
        pem = key.toPEM()
        self.assertEqual(pem, rsa_pem)

    def test_create_load_rsa(self):
        key = TSSPrivKey.create_rsa(self.ectx)
        key.load(self.ectx)

    def test_create_load_ecc(self):
        key = TSSPrivKey.create_ecc(self.ectx)
        key.load(self.ectx)

    def test_persistent_parent_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        inpublic = TPM2B_PUBLIC(publicArea=parent_rsa_template)
        parent, _, _, _, _ = self.ectx.create_primary(insens, inpublic)
        phandle = self.ectx.evict_control(
            ESYS_TR.RH_OWNER, parent, 0x81000081, session1=ESYS_TR.PASSWORD
        )

        key = TSSPrivKey.create_rsa(self.ectx, parent=0x81000081)
        key.load(self.ectx)
        self.assertEqual(key.parent, 0x81000081)

    def test_persistent_parent_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        inpublic = TPM2B_PUBLIC(publicArea=parent_ecc_template)
        parent, _, _, _, _ = self.ectx.create_primary(insens, inpublic)
        phandle = self.ectx.evict_control(
            ESYS_TR.RH_OWNER, parent, 0x81000081, session1=ESYS_TR.PASSWORD
        )

        key = TSSPrivKey.create_ecc(self.ectx, parent=0x81000081)
        key.load(self.ectx)
        self.assertEqual(key.parent, 0x81000081)
