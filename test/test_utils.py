#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2
import unittest

from tpm2_pytss import *
from tpm2_pytss.internal.crypto import (
    _generate_seed,
    private_to_key,
    public_to_key,
    _get_alg,
    _get_digest,
)
from tpm2_pytss.utils import *
from tpm2_pytss.internal.templates import _ek
from .TSS2_BaseTest import TSS2_EsapiTest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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

rsa_parent_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0FeMzAfnskx8eZYICdqURfwRhcgAWHkanaDZQXAMsKyBwkov
yso31lhQQpjghFv1hzxy9z9yvcE+7LnFWbTnhWH2PPYyR87iM6eaW9wGdaFLMX5R
8xbYG1ZJYsBOfiS4LauEHDYaAsYL9uv/5K0Dw2d/LSxzbv+9+EC3AomICZsf7m1B
BVQNvtWHaPBHH+19JGtGRg8KRBWRqnrzrx6WwpGtmHVNPJwOr5hz3FtOWj99STKc
oow5EIR44lrzg4dDcpyi4vWiustdZJm2j2iHKMfGu37r/mMDPjKNxY1YZQS5B8s5
lgxp76UBAfTm3mttyH1K79eoplgkA+qBglVqQQIDAQABAoIBAQCsA/0t4ED+x4Pm
Z2dPq3bMqahWCqGuap79EncOPlNb87JXFiWLi5a6lMP/mHWXEs4P0GsjlPFJlqo7
jc5RmLmnORCzmJo/C6Nb/r/FpE55BKkuvhsvV+cp+v4wWJL2N58RphE3sbucGqR6
RLRMvETlKyinxZGxTdothFEV+TOmqT4c3YXUyxTZj74oh+ovl22xopehxz/g9QwK
VdZa2bs9p5gxUeYlE3BQTt/YQAXDxPp2kTnWf8CjQ+f1YOlx+1OVJVaVPk5d3/8U
7CK5ljZoB5y11AYT11cxlqwphlF3ePJYIuTQHRldCO2Z7fv2GFJnVqKH+eu2/4AT
94RpHpyBAoGBAO1fOV0QL7ZQk0pJlY0yETrfZRkLcUM9lFzWnF8N/zfv4CcawZpw
PvSU5tTSnF/aYJn94KSKeZ/CiIJog4metlHNIc6qZBVTvh3lOGndib9YjLQ0j/Ru
gYITCMmffe74+RTD4yTmbCttoay3DzIX+rK9RMEg7SDRrHxmsWRoZzKpAoGBAOCx
HfG+FiZgJdWkelOgSBWG+9tcNmKyV+1wLR0XDx+Ung/0IWfhov4im6sPKKmKOALk
A2cKKkcByr57Y57oBS1oT8489G8rgR4hJlBZOU40N8HRLg+9FafFH5ObS29zUeis
AP/wq2l8DOlWUfRN1W8+YzamyOdDIGdgtGn1tFHZAoGBAKjxQS6POqYTqwEQZjRc
Eg9It/efQTmONm3tANZWa/Mv8uViEbENeoExCSknzMwb7O0s2BnDxNSD7AyEvjnQ
kAqgaRNiCmFzfLhiUEhouIVLTLllP5/ElsAxM+vsbAENipnQ4XV92jb+jDcVAuew
UWmtc6XQ/XSCRrUzkcXY2LohAoGAJiNqJcJSGClxwpWsfc1S7vR+g3lfcdk7u32y
6qEjXATp32Nc2DkgZWqSabKlAEIJx9PUEAVVr7/KHhLrkeloF5EBGsyV4NjNjcOq
sTCz3WZXoHpVCy7ZIiT/exp872nvmUK42LiNH9aCioiwWHttovg/9uLQbxChy2pK
tUGTXeECgYBYh3LsYNuWHpi2tW+cO3V4XP1AGBqZy3SDKD/Uk1jZPjEamkZCRDl2
9AGIGz0H+Ovfg8vzCgYj0E9KLlE63wjSsKajC+Z17+nwzvy9cFJJtqTq/7aR0niI
DoDguNqFEpw/cs8Eccbh0K43ubpLXc7xKoLGe5CF1sxEOZpYnPbyoA==
-----END RSA PRIVATE KEY-----
"""

ec_parent_key = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIODZrhXcbRQDOZUmzvYIWtU04ubMA7xTYnzsMs/LhwRUoAoGCCqGSM49
AwEHoUQDQgAEojRWBjpOkP4pH2fM5hha7iJj4A9RfDcbJrGTd181UMoYvfM+8VuY
Qa6C2sTmPHlvWopRgWslXt1JmxbBKwWf2Q==
-----END EC PRIVATE KEY-----
"""

ek_test_template = TPMT_PUBLIC(
    type=TPM2_ALG.KEYEDHASH,
    nameAlg=TPM2_ALG.SHA256,
    objectAttributes=TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN
    | TPMA_OBJECT.ADMINWITHPOLICY
    | TPMA_OBJECT.RESTRICTED
    | TPMA_OBJECT.SIGN_ENCRYPT,
    parameters=TPMU_PUBLIC_PARMS(
        keyedHashDetail=TPMS_KEYEDHASH_PARMS(
            scheme=TPMT_KEYEDHASH_SCHEME(
                scheme=TPM2_ALG.HMAC,
                details=TPMU_SCHEME_KEYEDHASH(
                    hmac=TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA256),
                ),
            )
        ),
    ),
)


class TestUtils(TSS2_EsapiTest):
    def test_generate_seed_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.create_primary(insens)
        _generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            _generate_seed(public.publicArea, b"test")
        self.assertEqual(
            str(e.exception), f"unsupported digest algorithm {TPM2_ALG.LAST + 1}"
        )

        public.publicArea.type = TPM2_ALG.NULL
        with self.assertRaises(ValueError) as e:
            _generate_seed(public.publicArea, b"test")
        self.assertEqual(str(e.exception), f"unsupported key type: {TPM2_ALG.NULL}")

    def test_generate_seed_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.create_primary(insens, "ecc")
        _generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            _generate_seed(public.publicArea, b"test")
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

    def test_make_credential_ecc_camellia(self):
        self.skipIfAlgNotSupported(TPM2_ALG.CAMELLIA)
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.create_primary(
            insens, "ecc:camellia128cfb"
        )
        self.assertEqual(
            parent.publicArea.parameters.eccDetail.symmetric.algorithm,
            TPM2_ALG.CAMELLIA,
        )
        private, public, _, _, _ = self.ectx.create(phandle, insens, "ecc")
        credblob, secret = make_credential(
            parent, b"credential data", public.get_name()
        )
        handle = self.ectx.load(phandle, private, public)
        certinfo = self.ectx.activate_credential(handle, phandle, credblob, secret)
        self.assertEqual(b"credential data", bytes(certinfo))

    def test_make_credential_ecc_sm4(self):
        if _get_alg(TPM2_ALG.SM4) is None:
            self.skipTest("SM4 is not supported by the cryptography module")
        elif _get_digest(TPM2_ALG.SM3_256) is None:
            self.skipTest("SM3 is not supported by the cryptography module")

        self.skipIfAlgNotSupported(TPM2_ALG.SM3_256)
        self.skipIfAlgNotSupported(TPM2_ALG.SM4)

        insens = TPM2B_SENSITIVE_CREATE()
        templ = TPM2B_PUBLIC.parse("ecc:sm4128cfb", nameAlg=TPM2_ALG.SM3_256)
        phandle, parent, _, _, _ = self.ectx.create_primary(insens, templ)
        self.assertEqual(
            parent.publicArea.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.SM4
        )
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

    def test_unwrap_rsa_parent_rsa_child(self):

        parent_priv = TPMT_SENSITIVE.from_pem(rsa_parent_key, password=None)
        parent = TPM2B_PUBLIC.from_pem(
            rsa_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        public = TPM2B_PUBLIC.from_pem(rsa_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(rsa_private_key)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"", None
        )

        unwrapped_sensitive = unwrap(
            parent.publicArea, parent_priv, public, duplicate, outsymseed
        )

        self.assertEqual(sensitive.marshal(), unwrapped_sensitive.marshal())

    def test_unwrap_rsa_parent_rsa_child_outerwrap(self):

        symdef = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        parent_priv = TPMT_SENSITIVE.from_pem(rsa_parent_key)
        parent = TPM2B_PUBLIC.from_pem(rsa_parent_key, symmetric=symdef)

        public = TPM2B_PUBLIC.from_pem(rsa_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(rsa_private_key)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"\xA1" * 16, symdef
        )

        unwrapped_sensitive = unwrap(
            parent.publicArea,
            parent_priv,
            public,
            duplicate,
            outsymseed,
            b"\xA1" * 16,
            symdef,
        )

        self.assertEqual(sensitive.marshal(), unwrapped_sensitive.marshal())

    def test_unwrap_ec_parent_rsa_child(self):

        parent_priv = TPMT_SENSITIVE.from_pem(ec_parent_key, password=None)
        parent = TPM2B_PUBLIC.from_pem(
            ec_parent_key,
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
        )

        public = TPM2B_PUBLIC.from_pem(rsa_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(rsa_private_key)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"", None
        )

        unwrapped_sensitive = unwrap(
            parent.publicArea, parent_priv, public, duplicate, outsymseed
        )

        self.assertEqual(sensitive.marshal(), unwrapped_sensitive.marshal())

    def test_unwrap_ec_parent_rsa_child_outerwrap(self):

        symdef = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        parent_priv = TPMT_SENSITIVE.from_pem(ec_parent_key, password=None)
        parent = TPM2B_PUBLIC.from_pem(ec_parent_key, symmetric=symdef)

        public = TPM2B_PUBLIC.from_pem(rsa_public_key)
        sensitive = TPM2B_SENSITIVE.from_pem(rsa_private_key)

        enckey, duplicate, outsymseed = wrap(
            parent.publicArea, public, sensitive, b"\xA1" * 16, symdef
        )

        unwrapped_sensitive = unwrap(
            parent.publicArea,
            parent_priv,
            public,
            duplicate,
            outsymseed,
            b"\xA1" * 16,
            symdef,
        )

        self.assertEqual(sensitive.marshal(), unwrapped_sensitive.marshal())

    def test_tpm_export_rsa_child_rsa_parent_with_inner_key(self):

        #
        # Step 1 - Create a TPM object to duplicate
        #
        phandle = self.ectx.create_primary(None)[0]

        # Create the child key, note we need to be able to enter the DUP role which requires
        # a policy session.
        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)
        policy_digest = self.ectx.policy_get_digest(session)
        self.ectx.flush_context(session)
        session = None
        in_pub = TPM2B_PUBLIC.parse(
            "rsa2048:aes128cfb",
            objectAttributes="userwithauth|restricted|decrypt|sensitivedataorigin",
            authPolicy=policy_digest,
        )
        tpm_priv, tpm_pub = self.ectx.create(phandle, None, in_pub)[:2]
        chandle = self.ectx.load(phandle, tpm_priv, tpm_pub)

        #
        # Step 2 - Duplicate it under a parent where you control the key. The parent MUST be a storage parent.
        #
        sym = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        parent = TPM2B_PUBLIC.from_pem(
            ec_parent_key,
            objectAttributes=TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.DECRYPT,
            symmetric=sym,
        )
        new_phandle = self.ectx.load_external(parent)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
                algorithm=TPM2_ALG.AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
            ),
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)

        encryptionKey = b"is sixteen bytes"

        # this is wrap performed by the TPM
        enckey, duplicate, outsymseed = self.ectx.duplicate(
            chandle, new_phandle, encryptionKey, sym, session1=session
        )

        #
        # Step 4 - unwrap with the new parent private key
        #
        parent_priv = TPMT_SENSITIVE.from_pem(ec_parent_key, password=None)

        unwrapped_sensitive = unwrap(
            parent.publicArea,
            parent_priv,
            tpm_pub,
            duplicate,
            outsymseed,
            encryptionKey,
            sym,
        )

        #
        # Step 5, validate the key by signing with the private key and verifying with the
        # public from create
        #
        priv_key = private_to_key(unwrapped_sensitive.sensitiveArea, tpm_pub.publicArea)

        message = b"A message I want to sign"
        signature = priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        pub_key = public_to_key(tpm_pub.publicArea)
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

    def test_create_ek_ecc(self):
        nv_read = NVReadEK(self.ectx)
        _, ecc_template = create_ek_template("EK-ECC256", nv_read)
        _, ecc, _, _, _ = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), ecc_template, ESYS_TR.ENDORSEMENT
        )

        self.assertEqual(ecc.publicArea.type, TPM2_ALG.ECC)

        ecc_nv_nonce = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1C0000B,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=15,
            )
        )
        eh = self.ectx.nv_define_space(b"", ecc_nv_nonce, ESYS_TR.OWNER)
        self.ectx.nv_write(eh, b"\xFF" * 15)
        nv_read = NVReadEK(self.ectx)
        _, ecc_nonce_template = create_ek_template("EK-ECC256", nv_read)
        _, ecc_nonce, _, _, _ = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), ecc_nonce_template, ESYS_TR.ENDORSEMENT
        )
        self.assertNotEqual(
            ecc_nonce.publicArea.unique.ecc.x, ecc.publicArea.unique.ecc.x
        )
        self.assertNotEqual(
            ecc_nonce.publicArea.unique.ecc.y, ecc.publicArea.unique.ecc.y
        )

    def test_create_ek_rsa(self):
        nv_read = NVReadEK(self.ectx)
        _, rsa_template = create_ek_template("EK-RSA2048", nv_read)
        _, rsa, _, _, _ = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), rsa_template, ESYS_TR.ENDORSEMENT
        )
        self.assertEqual(rsa.publicArea.type, TPM2_ALG.RSA)

        rsa_nv_nonce = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1C00003,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=127,
            )
        )
        rh = self.ectx.nv_define_space(b"", rsa_nv_nonce, ESYS_TR.OWNER)
        self.ectx.nv_write(rh, b"\xFF" * 127)
        nv_read = NVReadEK(self.ectx)
        _, rsa_nonce_template = create_ek_template("EK-RSA2048", nv_read)
        _, rsa_nonce, _, _, _ = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), rsa_nonce_template, ESYS_TR.ENDORSEMENT
        )
        self.assertNotEqual(rsa_nonce.publicArea.unique.rsa, rsa.publicArea.unique.rsa)

    def test_create_ek_template(self):
        tb = ek_test_template.marshal()
        nv_template = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1C0000C,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(tb),
            )
        )
        tnh = self.ectx.nv_define_space(b"", nv_template, ESYS_TR.OWNER)
        self.ectx.nv_write(tnh, tb)
        nv_read = NVReadEK(self.ectx)
        _, templpub = create_ek_template("EK-ECC256", nv_read)
        _, templ, _, _, _ = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), templpub, ESYS_TR.ENDORSEMENT
        )
        self.assertEqual(templ.publicArea.type, TPM2_ALG.KEYEDHASH)

    def test_create_ek_bad(self):
        nv_read = NVReadEK(self.ectx)
        with self.assertRaises(ValueError) as e:
            create_ek_template("EK-DES", nv_read)
        self.assertEqual(str(e.exception), "unknown EK type EK-DES")

    def test_create_ek_high_rsa2048(self):
        nv_read = NVReadEK(self.ectx)
        with self.assertRaises(ValueError) as e:
            create_ek_template("EK-HIGH-RSA2048", nv_read)
        self.assertEqual(str(e.exception), "no certificate found for EK-HIGH-RSA2048")

        cert_index, def_template = _ek.EK_HIGH_RSA2048
        nv_cert = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(b"I am a certificate"),
            )
        )
        cnh = self.ectx.nv_define_space(b"", nv_cert, ESYS_TR.OWNER)
        self.ectx.nv_write(cnh, b"I am a certificate")
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-RSA2048", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(template.marshal(), def_template.marshal())

        tb = ek_test_template.marshal()
        nv_template = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index + 1,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(tb),
            )
        )
        tnh = self.ectx.nv_define_space(b"", nv_template, ESYS_TR.OWNER)
        self.ectx.nv_write(tnh, tb)
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-RSA2048", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(
            template.marshal(), TPM2B_PUBLIC(publicArea=ek_test_template).marshal()
        )

    def test_create_ek_high_ecc256(self):
        nv_read = NVReadEK(self.ectx)
        with self.assertRaises(ValueError) as e:
            create_ek_template("EK-HIGH-ECC256", nv_read)
        self.assertEqual(str(e.exception), "no certificate found for EK-HIGH-ECC256")

        cert_index, def_template = _ek.EK_HIGH_ECC256
        nv_cert = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(b"I am a certificate"),
            )
        )
        cnh = self.ectx.nv_define_space(b"", nv_cert, ESYS_TR.OWNER)
        self.ectx.nv_write(cnh, b"I am a certificate")
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-ECC256", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(template.marshal(), def_template.marshal())

        tb = ek_test_template.marshal()
        nv_template = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index + 1,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(tb),
            )
        )
        tnh = self.ectx.nv_define_space(b"", nv_template, ESYS_TR.OWNER)
        self.ectx.nv_write(tnh, tb)
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-ECC256", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(
            template.marshal(), TPM2B_PUBLIC(publicArea=ek_test_template).marshal()
        )

    def test_create_ek_high_ecc384(self):
        nv_read = NVReadEK(self.ectx)
        with self.assertRaises(ValueError) as e:
            create_ek_template("EK-HIGH-ECC384", nv_read)
        self.assertEqual(str(e.exception), "no certificate found for EK-HIGH-ECC384")

        cert_index, def_template = _ek.EK_HIGH_ECC384
        nv_cert = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(b"I am a certificate"),
            )
        )
        cnh = self.ectx.nv_define_space(b"", nv_cert, ESYS_TR.OWNER)
        self.ectx.nv_write(cnh, b"I am a certificate")
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-ECC384", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(template.marshal(), def_template.marshal())

        tb = ek_test_template.marshal()
        nv_template = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=cert_index + 1,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
                dataSize=len(tb),
            )
        )
        tnh = self.ectx.nv_define_space(b"", nv_template, ESYS_TR.OWNER)
        self.ectx.nv_write(tnh, tb)
        nv_read = NVReadEK(self.ectx)
        cert, template = create_ek_template("EK-HIGH-ECC384", nv_read)
        self.assertEqual(cert, b"I am a certificate")
        self.assertEqual(
            template.marshal(), TPM2B_PUBLIC(publicArea=ek_test_template).marshal()
        )

    def test_unmarshal_tools_pcr_values(self):
        b64val = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////////////////////////////////////"
        buf = b64decode(b64val)
        sels = TPML_PCR_SELECTION.parse("sha1:8,9+sha256:17")
        n, digs = unmarshal_tools_pcr_values(buf, sels)
        self.assertEqual(n, 72)
        self.assertEqual(digs[0], b"\x00" * 20)
        self.assertEqual(digs[1], b"\x00" * 20)
        self.assertEqual(digs[2], b"\xFF" * 32)


if __name__ == "__main__":
    unittest.main()
