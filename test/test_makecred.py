#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import unittest

from tpm2_pytss import *
from tpm2_pytss.makecred import *
from .TSS2_BaseTest import TSS2_EsapiTest


rsa_private_key = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxU5SokcbkKjsgBGsQhBF70LM2yudAGPUiHbLObvNJSwDcN8L
TNN1Cg1+Q4VWb/jkEFEUMCHce6Rqq3xu+kTsj+J1BVfBIkxcNr7TdDCsgNiA4BX+
kGo4W0Z5y9AGiJNb2jjim+BoYwY67fGNKv2FE3BFdWLSoQcbdDAjStLw3yJ+nhz4
Op6dJRTyu8XWxYJwXziIAHBcNFAM7ipT9Yypv5+wZ8FyQizzUj321DruGzOPPKdy
ISbRYGeyq3s8oSlui+2zIiEOb428+OWzttgwz2jfwJ8NQGXTRp1Iw/L/xottZPkA
Yobff75SOv7or+sHlMpkLjtuftEhdpWnPIjXXwIDAQABAoIBAHFplvgulXqujtsC
zZhf0EM6i5SD2khKGfWjCygRelcemI+9tbogZksz/FsFfuz4DOgQIuGT5S+xD5uo
+AWlrrD6Q7ehfKOhbvQM9nD4NYAOcu3b1qreU6yrswDjf43r3kVuo1tkP7yD7UWu
ri2C8oZ854AVIOtssWw062RsIgavw5yYG7igUVehOxQPRfP6YezYI8qTYwUy1T2i
SQMcRzT5Q8KZnfPzJFse255X55Zf5reKDEruFtIQtHZl+FeL4wjb2xSQfIXV4KFa
zRGVRuNyBKLVG8TVwLZdmL4zRWG3gHoFcVCCaIOunhHbN8lqjDj35XOKqt7BBzNx
UrOrX4kCgYEA66V3YzEc0qTdqlTza2Il/eM/XoQStitQLLykZ/+yPWAgDr0XXAtg
atVctFU61sejXsd8zBxuBk2KrZ2dbrnzxszytiA2+pFzsY8g4XwA5+7Zs8yRrMAI
S6jNuuOBjseK8PfuEaO8wNbJGYxoEJtOvBl1M/U5HreaJsahnnuFmA0CgYEA1lkW
D+Xj/SEGZY2aPVGKYvtWYzzHBm2JKLh2GpG5RZheTqwFXo6XeG2G63ZkupH/pQOg
QXMIk4Lb/y6XapulmnLXprTQRFv+6b7sLA8u5DAAWmjbrRNU+iEuxkaDnaoHjxxK
SxCcg4jQPbNmC/YRh5DOaeNJm+19HGd+gj2HhhsCgYBdoyCvv8JOScjzeFJJ53Rl
ULnLmvu8e7WeMU+7K7XuAZZ7hNQVdUfY6/OsjPmWgzn93ZNPoDRwOLvUhX8bkrS1
2JbRnDd8lfO9KLzOHPJXN2g2tCFm3d/uAKPPkbvXup8RZdOqGsBUeITsrAhmIPDG
ee9CuDz8YcTVh7SNP1Q0uQKBgF88CZ9apudKiwsH1SW1WuULgqBo2oyykiQzgNXh
NQ4E2rHdoC0Y8ZeiIjXvzmVOhOUOLV+m+oJ/u7svOjs1mGh86e+5mmck8KduGoSg
4lakNSP2PtQxKKpRn/ScU9HzP5SIH0ImyUNvwAYJ9ScPV06COhO11nifFd1O5lh7
egFNAoGAUb6hqU4FE8DO8raO+dwTZBZqrlOldF7/L8aK2Xp98jkwtUIU0WLlo3AX
BWUSCMWPt/jlmVdZPb8jFkGTlkrpy8dSlZQ1oja8nlaxjXuSy57dYRVkDUGLfvsJ
1fG6ahkXCMzRx03YPkp2Yi/ZyRIdvlwKugQNPxx+qSWCauBvUY4=
-----END RSA PRIVATE KEY-----
"""

rsa_public_key = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxU5SokcbkKjsgBGsQhBF
70LM2yudAGPUiHbLObvNJSwDcN8LTNN1Cg1+Q4VWb/jkEFEUMCHce6Rqq3xu+kTs
j+J1BVfBIkxcNr7TdDCsgNiA4BX+kGo4W0Z5y9AGiJNb2jjim+BoYwY67fGNKv2F
E3BFdWLSoQcbdDAjStLw3yJ+nhz4Op6dJRTyu8XWxYJwXziIAHBcNFAM7ipT9Yyp
v5+wZ8FyQizzUj321DruGzOPPKdyISbRYGeyq3s8oSlui+2zIiEOb428+OWzttgw
z2jfwJ8NQGXTRp1Iw/L/xottZPkAYobff75SOv7or+sHlMpkLjtuftEhdpWnPIjX
XwIDAQAB
-----END PUBLIC KEY-----
"""

ecc_private_key = b"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMJI9ujmlT/qftbXWlMwOSpkxiWLAbyIMWEFPOqTbXYMoAoGCCqGSM49
AwEHoUQDQgAEgO/tHxp/YOuP4wAV3w66C8JNiSHOKSAYtlNKSN4ZDI//wn0f7zBv
Uc7FqaRPA9LL6k6C1YfdOi/yvTB7Y4Tgaw==
-----END EC PRIVATE KEY-----
"""

ecc_public_key = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgO/tHxp/YOuP4wAV3w66C8JNiSHO
KSAYtlNKSN4ZDI//wn0f7zBvUc7FqaRPA9LL6k6C1YfdOi/yvTB7Y4Tgaw==
-----END PUBLIC KEY-----
"""


class MakeCredTest(TSS2_EsapiTest):
    def test_generate_seed_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.create_primary(insens)
        seed, enc_seed = generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(
            str(e.exception), f"unsupported digest algorithm {TPM2_ALG.LAST + 1}"
        )

        public.publicArea.type = TPM2_ALG.NULL
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(str(e.exception), f"unsupported key type: {TPM2_ALG.NULL}")

    def test_generate_seed_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.create_primary(insens, "ecc")
        seed, enc_seed = generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(
            str(e.exception), f"unsupported digest algorithm {TPM2_ALG.LAST + 1}"
        )

    def test_MakeCredential_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.create_primary(insens)
        private, public, _, _, _ = self.ectx.create(phandle, insens)
        credblob, secret = make_credential(
            parent, b"credential data", public.get_name()
        )
        handle = self.ectx.load(phandle, private, public)
        certinfo = self.ectx.activate_credential(handle, phandle, credblob, secret)
        self.assertEqual(b"credential data", bytes(certinfo))

    def test_MakeCredential_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.create_primary(insens, "ecc")
        private, public, _, _, _ = self.ectx.create(phandle, insens, "ecc")
        credblob, secret = make_credential(
            parent, b"credential data", public.get_name()
        )
        handle = self.ectx.load(phandle, private, public)
        certinfo = self.ectx.activate_credential(handle, phandle, credblob, secret)
        self.assertEqual(b"credential data", bytes(certinfo))

    def test_Wrap_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.create_primary(insens)
        public = TPM2B_PUBLIC.from_pem(rsa_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(rsa_private_key)
        symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
        symdef.mode.sym = TPM2_ALG.CFB
        symdef.keyBits.sym = 128
        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"", symdef
        )

        self.ectx.import_(phandle, enckey, public, duplicate, outsymseed, symdef)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"", None
        )

        self.ectx.import_(
            phandle,
            enckey,
            public,
            duplicate,
            outsymseed,
            TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
        )

    def test_Wrap_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.create_primary(insens, "ecc")
        public = TPM2B_PUBLIC.from_pem(ecc_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(ecc_private_key)
        symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
        symdef.mode.sym = TPM2_ALG.CFB
        symdef.keyBits.sym = 128
        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"\xA1" * 16, symdef
        )

        self.ectx.import_(phandle, enckey, public, duplicate, outsymseed, symdef)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"", None
        )

        self.ectx.import_(
            phandle,
            enckey,
            public,
            duplicate,
            outsymseed,
            TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
        )
