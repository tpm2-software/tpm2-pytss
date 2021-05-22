#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import binascii
import itertools
import unittest

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_EsapiTest
from base64 import b64decode

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

rsa_public_key_bytes = b'\xc5NR\xa2G\x1b\x90\xa8\xec\x80\x11\xacB\x10E\xefB\xcc\xdb+\x9d\x00c\xd4\x88v\xcb9\xbb\xcd%,\x03p\xdf\x0bL\xd3u\n\r~C\x85Vo\xf8\xe4\x10Q\x140!\xdc{\xa4j\xab|n\xfaD\xec\x8f\xe2u\x05W\xc1"L\\6\xbe\xd3t0\xac\x80\xd8\x80\xe0\x15\xfe\x90j8[Fy\xcb\xd0\x06\x88\x93[\xda8\xe2\x9b\xe0hc\x06:\xed\xf1\x8d*\xfd\x85\x13pEub\xd2\xa1\x07\x1bt0#J\xd2\xf0\xdf"~\x9e\x1c\xf8:\x9e\x9d%\x14\xf2\xbb\xc5\xd6\xc5\x82p_8\x88\x00p\\4P\x0c\xee*S\xf5\x8c\xa9\xbf\x9f\xb0g\xc1rB,\xf3R=\xf6\xd4:\xee\x1b3\x8f<\xa7r!&\xd1`g\xb2\xab{<\xa1)n\x8b\xed\xb3"!\x0eo\x8d\xbc\xf8\xe5\xb3\xb6\xd80\xcfh\xdf\xc0\x9f\r@e\xd3F\x9dH\xc3\xf2\xff\xc6\x8bmd\xf9\x00b\x86\xdf\x7f\xbeR:\xfe\xe8\xaf\xeb\x07\x94\xcad.;n~\xd1!v\x95\xa7<\x88\xd7_'

rsa_private_key_bytes = b"\xeb\xa5wc1\x1c\xd2\xa4\xdd\xaaT\xf3kb%\xfd\xe3?^\x84\x12\xb6+P,\xbc\xa4g\xff\xb2=` \x0e\xbd\x17\\\x0b`j\xd5\\\xb4U:\xd6\xc7\xa3^\xc7|\xcc\x1cn\x06M\x8a\xad\x9d\x9dn\xb9\xf3\xc6\xcc\xf2\xb6 6\xfa\x91s\xb1\x8f \xe1|\x00\xe7\xee\xd9\xb3\xcc\x91\xac\xc0\x08K\xa8\xcd\xba\xe3\x81\x8e\xc7\x8a\xf0\xf7\xee\x11\xa3\xbc\xc0\xd6\xc9\x19\x8ch\x10\x9bN\xbc\x19u3\xf59\x1e\xb7\x9a&\xc6\xa1\x9e{\x85\x98\r"

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

ecc_public_key_bytes = b"\x80\xef\xed\x1f\x1a\x7f`\xeb\x8f\xe3\x00\x15\xdf\x0e\xba\x0b\xc2M\x89!\xce) \x18\xb6SJH\xde\x19\x0c\x8f\xff\xc2}\x1f\xef0oQ\xce\xc5\xa9\xa4O\x03\xd2\xcb\xeaN\x82\xd5\x87\xdd:/\xf2\xbd0{c\x84\xe0k"

ecc_private_key_bytes = b"\xc2H\xf6\xe8\xe6\x95?\xea~\xd6\xd7ZS09*d\xc6%\x8b\x01\xbc\x881a\x05<\xea\x93mv\x0c"

rsa_cert = b"""
-----BEGIN CERTIFICATE-----
MIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh
MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ
R0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB
IFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD
VQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD
VQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH
QShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn
25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr
R3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS
JRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT
ZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl
8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2
7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1
bdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d
cAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS
ghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu
81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV
HQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN
UltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M
BdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y
rkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ
gGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y
np8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2
DvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr
la5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf
Rdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR
pubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv
JpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM
6sJa8iBpdRjZrBp5sJBI
-----END CERTIFICATE-----
"""

ecc_cert = b"""
-----BEGIN CERTIFICATE-----
MIICWzCCAeKgAwIBAgIBBDAKBggqhkjOPQQDAzB3MQswCQYDVQQGEwJERTEhMB8G
A1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJR0Eo
VE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgRUNDIFJv
b3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYDVQQG
EwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQL
DBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShU
TSkgRUNDIFJvb3QgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQm1HxLVgvAu1q2
GM+ymTz12zdTEu0JBVG9CdsVEJv/pE7pSWOlsG3YwU792YAvjSy7zL+WtDK40KGe
Om8bSWt46QJ00MQUkYxz6YqXbb14BBr06hWD6u6IMBupNkPd9pKjQjBAMB0GA1Ud
DgQWBBS0GIXISkrFEnryQDnexPWLHn5K0TAOBgNVHQ8BAf8EBAMCAAYwDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjA6QZcV8DjjbPuKjKDZQmTRywZk
MAn8wE6kuW3EouVvBt+/2O+szxMe4vxj8R6TDCYCMG7c9ov86ll/jDlJb/q0L4G+
+O3Bdel9P5+cOgzIGANkOPEzBQM3VfJegfnriT/kaA==
-----END CERTIFICATE-----
"""


class CryptoTest(TSS2_EsapiTest):
    def test_public_from_pem_rsa(self):
        pub = types.TPM2B_PUBLIC()
        crypto.public_from_encoding(rsa_public_key, pub.publicArea)

        self.assertEqual(pub.publicArea.type, types.TPM2_ALG.RSA)
        self.assertEqual(pub.publicArea.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(pub.publicArea.parameters.rsaDetail.exponent, 0)
        self.assertEqual(bytes(pub.publicArea.unique.rsa.buffer), rsa_public_key_bytes)

    def test_private_from_pem_rsa(self):
        priv = types.TPM2B_SENSITIVE()
        crypto.private_from_encoding(rsa_private_key, priv)

        self.assertEqual(priv.sensitiveArea.sensitiveType, types.TPM2_ALG.RSA)
        self.assertEqual(
            bytes(priv.sensitiveArea.sensitive.rsa.buffer), rsa_private_key_bytes
        )

    def test_loadexternal_rsa(self):
        pub = types.TPM2B_PUBLIC.fromPEM(rsa_public_key)
        self.assertEqual(pub.publicArea.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            pub.publicArea.objectAttributes,
            (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH),
        )
        self.assertEqual(
            pub.publicArea.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL
        )
        self.assertEqual(
            pub.publicArea.parameters.rsaDetail.scheme.scheme, TPM2_ALG.NULL
        )

        priv = types.TPM2B_SENSITIVE.fromPEM(rsa_private_key)

        # test without Hierarchy
        handle = self.ectx.LoadExternal(priv, pub)
        self.assertNotEqual(handle, 0)

        # negative test
        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(TPM2B_PUBLIC(), pub)

        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(priv, priv)

        with self.assertRaises(ValueError):
            self.ectx.LoadExternal(priv, pub, 7467644)

        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(priv, pub, object)

        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(priv, pub, session1=76.5)

        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(priv, pub, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.LoadExternal(priv, pub, session3=TPM2B_PUBLIC())

    def test_public_from_pem_ecc(self):
        pub = types.TPM2B_PUBLIC()
        crypto.public_from_encoding(ecc_public_key, pub.publicArea)

        self.assertEqual(pub.publicArea.type, types.TPM2_ALG.ECC)
        self.assertEqual(
            pub.publicArea.parameters.eccDetail.curveID, types.TPM2_ECC.NIST_P256
        )
        self.assertEqual(
            bytes(pub.publicArea.unique.ecc.x.buffer), ecc_public_key_bytes[0:32]
        )
        self.assertEqual(
            bytes(pub.publicArea.unique.ecc.y.buffer), ecc_public_key_bytes[32:64]
        )

    def test_private_from_pem_ecc(self):
        priv = types.TPM2B_SENSITIVE()
        crypto.private_from_encoding(ecc_private_key, priv)

        self.assertEqual(priv.sensitiveArea.sensitiveType, types.TPM2_ALG.ECC)
        self.assertEqual(
            bytes(priv.sensitiveArea.sensitive.ecc.buffer), ecc_private_key_bytes
        )

    def test_loadexternal_ecc(self):
        pub = types.TPM2B_PUBLIC.fromPEM(ecc_public_key)
        self.assertEqual(pub.publicArea.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            pub.publicArea.objectAttributes,
            (TPMA_OBJECT.DECRYPT | TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH),
        )
        self.assertEqual(
            pub.publicArea.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.NULL
        )
        self.assertEqual(
            pub.publicArea.parameters.eccDetail.scheme.scheme, TPM2_ALG.NULL
        )
        self.assertEqual(pub.publicArea.parameters.eccDetail.kdf.scheme, TPM2_ALG.NULL)

        priv = types.TPM2B_SENSITIVE.fromPEM(ecc_private_key)

        self.ectx.LoadExternal(priv, pub, types.ESYS_TR.RH_NULL)

    def test_loadexternal_public_rsa(self):
        pub = types.TPM2B_PUBLIC.fromPEM(rsa_public_key)
        self.ectx.LoadExternal(None, pub, types.ESYS_TR.RH_NULL)

    def test_public_to_pem_rsa(self):
        pub = types.TPM2B_PUBLIC.fromPEM(rsa_public_key)
        pem = crypto.public_to_pem(pub.publicArea)

        self.assertEqual(pem, rsa_public_key)

    def test_public_to_pem_ecc(self):
        pub = types.TPM2B_PUBLIC.fromPEM(ecc_public_key)
        pem = crypto.public_to_pem(pub.publicArea)

        self.assertEqual(pem, ecc_public_key)

    def test_topem_rsa(self):
        pub = types.TPM2B_PUBLIC.fromPEM(rsa_public_key)
        pem = pub.toPEM()

        self.assertEqual(pem, rsa_public_key)

    def test_topem_ecc(self):
        pub = types.TPM2B_PUBLIC.fromPEM(ecc_public_key)
        pem = pub.toPEM()

        self.assertEqual(pem, ecc_public_key)

    def test_public_getname(self):
        pub = types.TPM2B_PUBLIC.fromPEM(ecc_public_key)
        priv = types.TPM2B_SENSITIVE.fromPEM(ecc_private_key)
        handle = self.ectx.LoadExternal(priv, pub, types.ESYS_TR.RH_NULL)
        ename = self.ectx.TR_GetName(handle)
        oname = pub.getName()

        self.assertEqual(ename.name, oname.name)

    def test_nv_getname(self):
        nv = TPMS_NV_PUBLIC(
            nvIndex=0x1000000,
            nameAlg=TPM2_ALG.SHA1,
            attributes=TPMA_NV.AUTHREAD | TPMA_NV.AUTHWRITE,
            dataSize=123,
        )
        oname = nv.getName()
        nv2b = TPM2B_NV_PUBLIC(nvPublic=nv)

        handle = self.ectx.NV_DefineSpace(b"1234", nv2b)

        ename = self.ectx.TR_GetName(handle)

        self.assertEqual(ename.name, oname.name)

    def test_public_from_pem_rsa_pem_cert(self):
        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(rsa_cert, pub)

    def test_public_from_pem_rsa_der_cert(self):
        sl = rsa_cert.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(der, pub)

    def test_public_from_pem_ecc_pem_cert(self):
        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(ecc_cert, pub)

    def test_public_from_pem_ecc_der_cert(self):
        sl = ecc_cert.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(der, pub)

    def test_public_from_pem_rsa_der(self):
        sl = rsa_public_key.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(der, pub)

    def test_public_from_pem_ecc_der(self):
        sl = ecc_public_key.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        pub = TPMT_PUBLIC()
        crypto.public_from_encoding(der, pub)

    def test_public_from_pem_bad_der(self):
        der = b"" * 1024
        pub = TPMT_PUBLIC()
        with self.assertRaises(ValueError) as e:
            crypto.public_from_encoding(der, pub)
        self.assertEqual(str(e.exception), "Unsupported key format")

    def test_private_from_pem_rsa_der(self):
        sl = rsa_private_key.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        sens = TPM2B_SENSITIVE()
        crypto.private_from_encoding(der, sens)

    def test_private_from_pem_ecc_der(self):
        sl = ecc_private_key.strip().splitlines()
        b64 = b"".join(sl[1:-1])
        der = b64decode(b64)

        sens = TPM2B_SENSITIVE()
        crypto.private_from_encoding(der, sens)

    def test_private_from_pem_bad_der(self):
        der = b"" * 1024
        pub = TPM2B_PUBLIC()
        with self.assertRaises(ValueError) as e:
            crypto.private_from_encoding(der, pub)
        self.assertEqual(str(e.exception), "Unsupported key format")
