#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-3
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey, _parent_rsa_template, _parent_ecc_template
from .TSS2_BaseTest import TSS2_EsapiTest
from asn1crypto.core import ObjectIdentifier
from asn1crypto import pem

import unittest

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
        key = TSSPrivKey.from_pem(rsa_pem)

    def test_rsa_topem(self):
        key = TSSPrivKey.from_pem(rsa_pem)
        pem = key.to_pem()
        self.assertEqual(pem, rsa_pem)

    def test_create_load_rsa(self):
        key = TSSPrivKey.create_rsa(self.ectx)
        key.load(self.ectx)

    def test_create_load_ecc(self):
        key = TSSPrivKey.create_ecc(self.ectx)
        key.load(self.ectx)

    def test_create_load_ecc_password(self):
        key = TSSPrivKey.create_ecc(self.ectx, password=b"1234")
        key.load(self.ectx, password=b"1234")

    def test_create_password_load_no_password(self):
        key = TSSPrivKey.create_ecc(self.ectx, password=b"1234")
        with self.assertRaises(RuntimeError) as e:
            key.load(self.ectx)
        self.assertEqual(str(e.exception), "no password specified but it is required")

    def test_create_no_password_load_password(self):
        key = TSSPrivKey.create_ecc(self.ectx)
        with self.assertWarns(UserWarning) as w:
            key.load(self.ectx, password=b"1234")
        self.assertEqual(str(w.warning), "password specified but empty_auth is true")

    def test_persistent_parent_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        inpublic = TPM2B_PUBLIC(publicArea=_parent_rsa_template)
        parent, _, _, _, _ = self.ectx.create_primary(insens, inpublic)
        phandle = self.ectx.evict_control(
            ESYS_TR.RH_OWNER, parent, 0x81000081, session1=ESYS_TR.PASSWORD
        )

        key = TSSPrivKey.create_rsa(self.ectx, parent=0x81000081)
        key.load(self.ectx)
        self.assertEqual(key.parent, 0x81000081)

    def test_persistent_parent_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        inpublic = TPM2B_PUBLIC(publicArea=_parent_ecc_template)
        parent, _, _, _, _ = self.ectx.create_primary(insens, inpublic)
        phandle = self.ectx.evict_control(
            ESYS_TR.RH_OWNER, parent, 0x81000081, session1=ESYS_TR.PASSWORD
        )

        key = TSSPrivKey.create_ecc(self.ectx, parent=0x81000081)
        key.load(self.ectx)
        self.assertEqual(key.parent, 0x81000081)

    def test_bad_pem_type(self):
        bad_pem = rsa_pem.replace(b"TSS2", b"BORK")
        with self.assertRaises(TypeError) as e:
            TSSPrivKey.from_pem(bad_pem)
        self.assertEqual(str(e.exception), "unsupported PEM type")

    def test_bad_oid(self):
        _, _, der = pem.unarmor(rsa_pem)
        dc = TSSPrivKey._tssprivkey_der.load(der)
        dc["type"] = ObjectIdentifier("1.2.3.4")
        badder = dc.dump()

        with self.assertRaises(TypeError) as e:
            TSSPrivKey.from_der(badder)
        self.assertEqual(str(e.exception), "unsupported key type")

    def test_no_ecc(self):
        cap_data = TPMS_CAPABILITY_DATA()
        cap_data.data.algorithms[0] = TPMS_ALG_PROPERTY(alg=TPM2_ALG.RSA)

        def mock_getcap(*args, **kwargs):
            return (False, cap_data)

        self.ectx.get_capability = mock_getcap

        TSSPrivKey.create_ecc(self.ectx)

    def test_no_ecc_no_rsa(self):
        cap_data = TPMS_CAPABILITY_DATA()

        def mock_getcap(*args, **kwargs):
            return (False, cap_data)

        self.ectx.get_capability = mock_getcap

        with self.assertRaises(RuntimeError) as e:
            TSSPrivKey.create_ecc(self.ectx)
        self.assertEqual(str(e.exception), "Unable to find supported parent key type")


if __name__ == "__main__":
    unittest.main()
