#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import unittest

from tpm2_pytss import *
from tpm2_pytss.encoding import (
    base_encdec,
    json_encdec,
    tools_encdec,
    to_yaml,
    from_yaml,
)
from tpm2_pytss.internal.utils import TSS2Version
from binascii import unhexlify, hexlify
from .TSS2_BaseTest import TSS2_BaseTest
import shutil
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import subprocess
import sys
import os


class SerializationTest(unittest.TestCase):
    def test_base_simple_tpm2b(self):
        enc = base_encdec()
        dig = TPM2B_DIGEST(b"falafel")
        ev = enc.encode(dig)
        self.assertEqual(ev, "66616c6166656c")

    def test_base_friendly_int(self):
        enc = base_encdec()
        ev = enc.encode(TPM2_ALG.SHA256)
        self.assertEqual(ev, 0x0B)

    def test_base_friendly_intlist(self):
        enc = base_encdec()
        ev = enc.encode(TPMA_OBJECT(TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.FIXEDTPM))
        self.assertEqual(ev, 0x10002)

    def test_base_int(self):
        enc = base_encdec()
        ev = enc.encode(1337)
        self.assertEqual(ev, 1337)

    def test_base_complex_tpm2b(self):
        enc = base_encdec()
        p = TPM2B_ECC_POINT(TPMS_ECC_POINT(x=b"\x01", y="\x02"))
        ev = enc.encode(p)
        self.assertEqual(ev, {"x": "01", "y": "02"})

    def test_base_tpml(self):
        enc = base_encdec()
        al = TPML_ALG((TPM2_ALG.SHA256, TPM2_ALG.SHA384, TPM2_ALG.SHA512))
        ev = enc.encode(al)
        self.assertEqual(ev, [TPM2_ALG.SHA256, TPM2_ALG.SHA384, TPM2_ALG.SHA512])

    def test_base_TPMS_CAPABILITY_DATA(self):
        enc = base_encdec()
        algs = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.ALGS)
        algs.data.algorithms = TPML_ALG_PROPERTY(
            (TPMS_ALG_PROPERTY(alg=TPM2_ALG.SHA256, algProperties=TPMA_ALGORITHM.HASH),)
        )
        ev = enc.encode(algs)
        self.assertEqual(
            ev, {"capability": 0, "data": [{"alg": 11, "algProperties": 4}]}
        )

        handles = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.HANDLES)
        handles.data.handles = TPML_HANDLE((1,))
        ev = enc.encode(handles)
        self.assertEqual(ev, {"capability": 1, "data": [1,]})

        commands = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.COMMANDS)
        cmd = TPM2_CC.NV_Write & TPMA_CC.NV & (2 << TPMA_CC.CHANDLES_SHIFT)
        commands.data.command = TPML_CCA((cmd,))
        ev = enc.encode(commands)
        self.assertEqual(ev, {"capability": 2, "data": [cmd,]})

        ppcommands = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.PP_COMMANDS)
        ppcommands.data.ppCommands = TPML_CC((3,))
        ev = enc.encode(ppcommands)
        self.assertEqual(ev, {"capability": 3, "data": [3,]})

        auditcommands = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.AUDIT_COMMANDS)
        auditcommands.data.auditCommands = TPML_CC((4,))
        ev = enc.encode(auditcommands)
        self.assertEqual(ev, {"capability": 4, "data": [4,]})

        pcrs = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.PCRS)
        pcrsel = TPMS_PCR_SELECTION(
            hash=TPM2_ALG.SHA256, sizeofSelect=3, pcrSelect=b"\x81\x00\x00"
        )
        pcrs.data.assignedPCR = TPML_PCR_SELECTION((pcrsel,))
        ev = enc.encode(pcrs)
        self.assertEqual(
            ev, {"capability": 5, "data": [{"hash": 0x0B, "pcrSelect": [0, 7]}]}
        )

        tpm = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.TPM_PROPERTIES)
        prop = TPMS_TAGGED_PROPERTY(property=TPM2_PT_NV.BUFFER_MAX, value=0x300)
        tpm.data.tpmProperties = TPML_TAGGED_TPM_PROPERTY((prop,))
        ev = enc.encode(tpm)
        self.assertEqual(
            ev, {"capability": 6, "data": [{"property": 300, "value": 0x300}]}
        )

        pcrs = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.PCR_PROPERTIES)
        pprop = TPMS_TAGGED_PCR_SELECT(
            tag=TPM2_PT_PCR.DRTM_RESET, sizeofSelect=3, pcrSelect=b"\xFF\x00\x00"
        )
        pcrs.data.pcrProperties = TPML_TAGGED_PCR_PROPERTY((pprop,))
        ev = enc.encode(pcrs)
        self.assertEqual(
            ev,
            {
                "capability": 7,
                "data": [{"tag": 0x12, "pcrSelect": [0, 1, 2, 3, 4, 5, 6, 7]}],
            },
        )

        curves = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.ECC_CURVES)
        curves.data.eccCurves = TPML_ECC_CURVE((TPM2_ECC.SM2_P256,))
        ev = enc.encode(curves)
        self.assertEqual(ev, {"capability": 8, "data": [0x20,]})

    def test_base_TPMS_ATTEST(self):
        enc = base_encdec()
        certify = TPMS_ATTEST(type=TPM2_ST.ATTEST_CERTIFY)
        certify.attested.certify = TPMS_CERTIFY_INFO(
            name=b"\x01", qualifiedName=b"\x02"
        )
        ev = enc.encode(certify)
        self.assertEqual(ev["type"], 0x8017)
        self.assertEqual(ev["attested"], {"name": "01", "qualifiedName": "02"})

        creation = TPMS_ATTEST(type=TPM2_ST.ATTEST_CREATION)
        creation.attested.creation = TPMS_CREATION_INFO(
            objectName=b"\x01", creationHash=b"\x02"
        )
        ev = enc.encode(creation)
        self.assertEqual(ev["type"], 0x801A)
        self.assertEqual(ev["attested"], {"objectName": "01", "creationHash": "02"})

        quote = TPMS_ATTEST(type=TPM2_ST.ATTEST_QUOTE)
        sel = TPMS_PCR_SELECTION(
            hash=TPM2_ALG.SHA256, sizeofSelect=3, pcrSelect=b"\x00\x81\x00"
        )
        quote.attested.quote = TPMS_QUOTE_INFO(
            pcrSelect=TPML_PCR_SELECTION((sel,)), pcrDigest=b"\x01" * 32
        )
        ev = enc.encode(quote)
        self.assertEqual(ev["type"], 0x8018)
        self.assertEqual(
            ev["attested"],
            {
                "pcrSelect": [{"hash": TPM2_ALG.SHA256, "pcrSelect": [8, 15]}],
                "pcrDigest": "01" * 32,
            },
        )

        command = TPMS_ATTEST(type=TPM2_ST.ATTEST_COMMAND_AUDIT)
        command.attested.commandAudit = TPMS_COMMAND_AUDIT_INFO(
            auditCounter=1337,
            digestAlg=TPM2_ALG.SHA256,
            auditDigest=b"\x01",
            commandDigest=b"\x02",
        )
        ev = enc.encode(command)
        self.assertEqual(ev["type"], TPM2_ST.ATTEST_COMMAND_AUDIT)
        self.assertEqual(
            ev["attested"],
            {
                "auditCounter": 1337,
                "digestAlg": TPM2_ALG.SHA256,
                "auditDigest": "01",
                "commandDigest": "02",
            },
        )

        session = TPMS_ATTEST(type=TPM2_ST.ATTEST_SESSION_AUDIT)
        session.attested.sessionAudit = TPMS_SESSION_AUDIT_INFO(
            exclusiveSession=True, sessionDigest=b"\x01"
        )
        ev = enc.encode(session)
        self.assertEqual(ev["type"], TPM2_ST.ATTEST_SESSION_AUDIT)
        self.assertEqual(ev["attested"], {"exclusiveSession": 1, "sessionDigest": "01"})

        time = TPMS_ATTEST(type=TPM2_ST.ATTEST_TIME)
        time.attested.time = TPMS_TIME_ATTEST_INFO(
            time=TPMS_TIME_INFO(
                time=1234,
                clockInfo=TPMS_CLOCK_INFO(
                    clock=1024, resetCount=2, restartCount=3, safe=False,
                ),
            ),
            firmwareVersion=1337,
        )
        ev = enc.encode(time)
        self.assertEqual(ev["type"], TPM2_ST.ATTEST_TIME)
        self.assertEqual(
            ev["attested"],
            {
                "firmwareVersion": 1337,
                "time": {
                    "time": 1234,
                    "clockInfo": {
                        "clock": 1024,
                        "resetCount": 2,
                        "restartCount": 3,
                        "safe": 0,
                    },
                },
            },
        )

        nv = TPMS_ATTEST(type=TPM2_ST.ATTEST_NV)
        nv.attested.nv = TPMS_NV_CERTIFY_INFO(
            indexName=b"\x01", offset=2, nvContents=b"\x03"
        )
        ev = enc.encode(nv)
        self.assertEqual(ev["type"], TPM2_ST.ATTEST_NV)
        self.assertEqual(
            ev["attested"], {"indexName": "01", "offset": 2, "nvContents": "03"}
        )

    def test_base_TPMT_SYM_DEF(self):
        enc = base_encdec()
        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.AES)
        sym.keyBits.aes = 128
        sym.mode.aes = TPM2_ALG.CFB
        ev = enc.encode(sym)
        self.assertEqual(
            ev, {"algorithm": TPM2_ALG.AES, "keyBits": 128, "mode": TPM2_ALG.CFB}
        )

        xor = TPMT_SYM_DEF(algorithm=TPM2_ALG.XOR)
        xor.keyBits.exclusiveOr = TPM2_ALG.SHA1
        ev = enc.encode(xor)
        self.assertEqual(ev, {"algorithm": TPM2_ALG.XOR, "keyBits": TPM2_ALG.SHA1})

    def test_base_TPMT_KEYEDHASH_SCHEME(self):
        enc = base_encdec()
        hmac = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.HMAC)
        hmac.details.hmac.hashAlg = TPM2_ALG.SHA256
        ev = enc.encode(hmac)
        self.assertEqual(
            ev, {"scheme": TPM2_ALG.HMAC, "details": {"hashAlg": TPM2_ALG.SHA256}}
        )

        xor = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.XOR)
        xor.details.exclusiveOr = TPMS_SCHEME_XOR(
            hashAlg=TPM2_ALG.SHA256, kdf=TPM2_ALG.KDF2
        )
        ev = enc.encode(xor)
        self.assertEqual(
            ev,
            {
                "scheme": TPM2_ALG.XOR,
                "details": {"hashAlg": TPM2_ALG.SHA256, "kdf": TPM2_ALG.KDF2},
            },
        )

    def test_base_TPMT_SIG_SCHEME(self):
        enc = base_encdec()
        ecdaa = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDAA)
        ecdaa.details.ecdaa = TPMS_SCHEME_ECDAA(hashAlg=TPM2_ALG.SHA256, count=2)
        ev = enc.encode(ecdaa)
        self.assertEqual(
            ev,
            {
                "scheme": TPM2_ALG.ECDAA,
                "details": {"hashAlg": TPM2_ALG.SHA256, "count": 2},
            },
        )

        sig = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
        sig.details.any.hashAlg = TPM2_ALG.SHA256
        ev = enc.encode(sig)
        self.assertEqual(
            ev, {"scheme": TPM2_ALG.ECDSA, "details": {"hashAlg": TPM2_ALG.SHA256}}
        )

    def test_base_TPMT_KDF_SCHEME(self):
        enc = base_encdec()
        kdf = TPMT_KDF_SCHEME(scheme=TPM2_ALG.KDF2)
        kdf.details.mgf1.hashAlg = TPM2_ALG.SHA256
        ev = enc.encode(kdf)
        self.assertEqual(
            ev, {"scheme": TPM2_ALG.KDF2, "details": {"hashAlg": TPM2_ALG.SHA256}}
        )

    def test_base_TPMT_ASYM_SCHEME(self):
        enc = base_encdec()
        ecdaa = TPMT_ASYM_SCHEME(scheme=TPM2_ALG.ECDAA)
        ecdaa.details.ecdaa = TPMS_SCHEME_ECDAA(hashAlg=TPM2_ALG.SHA256, count=2)
        ev = enc.encode(ecdaa)
        self.assertEqual(
            ev,
            {
                "scheme": TPM2_ALG.ECDAA,
                "details": {"count": 2, "hashAlg": TPM2_ALG.SHA256},
            },
        )

        rsaes = TPMT_ASYM_SCHEME(scheme=TPM2_ALG.RSAES)
        ev = enc.encode(rsaes)
        self.assertEqual(ev, {"scheme": TPM2_ALG.RSAES})

        scheme = TPMT_ASYM_SCHEME(scheme=TPM2_ALG.RSASSA)
        scheme.details.rsassa.hashAlg = TPM2_ALG.SHA256
        ev = enc.encode(scheme)
        self.assertEqual(
            ev, {"scheme": TPM2_ALG.RSASSA, "details": {"hashAlg": TPM2_ALG.SHA256}}
        )

    def test_base_TPMT_SINGATURE(self):
        enc = base_encdec()
        rsa = TPMT_SIGNATURE(sigAlg=TPM2_ALG.RSASSA)
        rsa.signature.rsassa = TPMS_SIGNATURE_RSA(hash=TPM2_ALG.SHA256, sig=b"\x01")
        ev = enc.encode(rsa)
        self.assertEqual(
            ev,
            {
                "sigAlg": TPM2_ALG.RSASSA,
                "signature": {"hash": TPM2_ALG.SHA256, "sig": "01"},
            },
        )

        ecc = TPMT_SIGNATURE(sigAlg=TPM2_ALG.ECDSA)
        ecc.signature.ecdsa = TPMS_SIGNATURE_ECC(
            hash=TPM2_ALG.SHA256, signatureR=b"\x02", signatureS=b"\x03"
        )
        ev = enc.encode(ecc)
        self.assertEqual(
            ev,
            {
                "sigAlg": TPM2_ALG.ECDSA,
                "signature": {
                    "hash": TPM2_ALG.SHA256,
                    "signatureR": "02",
                    "signatureS": "03",
                },
            },
        )

        hmac = TPMT_SIGNATURE(sigAlg=TPM2_ALG.HMAC)
        hmac.signature.hmac.hashAlg = TPM2_ALG.SHA256
        hmac.signature.hmac.digest.sha256 = b"\x01" * 32
        ev = enc.encode(hmac)
        self.assertEqual(
            ev,
            {
                "sigAlg": TPM2_ALG.HMAC,
                "signature": {"hashAlg": TPM2_ALG.SHA256, "digest": "01" * 32},
            },
        )

    def test_base_TPMT_PUBLIC_PARMS(self):
        enc = base_encdec()
        keyedhash = TPMT_PUBLIC_PARMS(type=TPM2_ALG.KEYEDHASH)
        keyedhash.parameters.keyedHashDetail.scheme = TPMT_KEYEDHASH_SCHEME(
            scheme=TPM2_ALG.HMAC
        )
        keyedhash.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = (
            TPM2_ALG.SHA256
        )
        ev = enc.encode(keyedhash)
        self.assertEqual(ev["type"], TPM2_ALG.KEYEDHASH)
        self.assertEqual(
            ev["parameters"],
            {
                "scheme": {
                    "details": {"hashAlg": TPM2_ALG.SHA256},
                    "scheme": TPM2_ALG.HMAC,
                },
            },
        )

        sym = TPMT_PUBLIC_PARMS(type=TPM2_ALG.SYMCIPHER)
        sym.parameters.symDetail.sym = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
        sym.parameters.symDetail.sym.keyBits.aes = 128
        sym.parameters.symDetail.sym.mode.aes = TPM2_ALG.CFB
        ev = enc.encode(sym)
        self.assertEqual(ev["type"], TPM2_ALG.SYMCIPHER)
        self.assertEqual(
            ev["parameters"],
            {"sym": {"algorithm": TPM2_ALG.AES, "keyBits": 128, "mode": TPM2_ALG.CFB}},
        )

        rsa = TPMT_PUBLIC_PARMS(type=TPM2_ALG.RSA)
        parms = TPMS_RSA_PARMS(keyBits=2048)
        parms.symmetric.algorithm = TPM2_ALG.NULL
        parms.scheme.scheme = TPM2_ALG.NULL
        rsa.parameters.rsaDetail = parms
        ev = enc.encode(rsa)
        self.assertEqual(ev["type"], TPM2_ALG.RSA)
        self.assertEqual(
            ev["parameters"],
            {
                "exponent": 0,
                "keyBits": 2048,
                "scheme": {"scheme": TPM2_ALG.NULL},
                "symmetric": {"algorithm": TPM2_ALG.NULL},
            },
        )

        ecc = TPMT_PUBLIC_PARMS(type=TPM2_ALG.ECC)
        parms = TPMS_ECC_PARMS(curveID=TPM2_ALG.SM2)
        parms.symmetric.algorithm = TPM2_ALG.NULL
        parms.scheme.scheme = TPM2_ALG.NULL
        parms.kdf.scheme = TPM2_ALG.NULL
        ecc.parameters.eccDetail = parms
        ev = enc.encode(ecc)
        self.assertEqual(ev["type"], TPM2_ALG.ECC)
        self.assertEqual(
            ev["parameters"],
            {
                "curveID": TPM2_ALG.SM2,
                "kdf": {"scheme": TPM2_ALG.NULL},
                "scheme": {"scheme": TPM2_ALG.NULL},
                "symmetric": {"algorithm": TPM2_ALG.NULL},
            },
        )

    def test_base_TPMT_PUBLIC(self):
        enc = base_encdec()
        keyedhash = TPMT_PUBLIC(type=TPM2_ALG.KEYEDHASH)
        keyedhash.unique.keyedHash = b"\x22" * 32
        keyedhash.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
        ev = enc.encode(keyedhash)
        self.assertEqual(ev["type"], TPM2_ALG.KEYEDHASH)
        self.assertEqual(ev["unique"], "22" * 32)

        rsa = TPMT_PUBLIC(type=TPM2_ALG.RSA)
        rsa.unique.rsa = b"\x33" * 32
        ev = enc.encode(rsa)
        self.assertEqual(ev["type"], TPM2_ALG.RSA)
        self.assertEqual(ev["unique"], "33" * 32)

        ecc = TPMT_PUBLIC(type=TPM2_ALG.ECC)
        ecc.unique.ecc.x = b"\x04"
        ecc.unique.ecc.y = b"\x05"
        ev = enc.encode(ecc)
        self.assertEqual(ev["type"], TPM2_ALG.ECC)
        self.assertEqual(ev["unique"], {"x": "04", "y": "05"})

    def test_base_TPMT_SENSITIVE(self):
        enc = base_encdec()
        rsa = TPMT_SENSITIVE(sensitiveType=TPM2_ALG.RSA)
        rsa.sensitive.rsa = b"\x11" * 32
        ev = enc.encode(rsa)
        self.assertEqual(ev["sensitiveType"], TPM2_ALG.RSA)
        self.assertEqual(ev["sensitive"], "11" * 32)

    def test_base_bad(self):
        enc = base_encdec()
        with self.assertRaises(TypeError) as e:
            enc.encode(TPMU_KDF_SCHEME())
        self.assertEqual(str(e.exception), "tried to encode union TPMU_KDF_SCHEME")

        with self.assertRaises(ValueError) as e:
            null = TPMT_PUBLIC(type=TPM2_ALG.NULL)
            enc.encode(null)
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field parameters in TPMT_PUBLIC",
        )

        with self.assertRaises(TypeError) as e:
            enc.encode(list())
        self.assertEqual(str(e.exception), "unable to encode value of type list")

    def test_base_decode_friendly_intlist(self):
        dec = base_encdec()
        attrs = int(TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.DECRYPT)
        dv = dec.decode(TPMA_OBJECT(), attrs)
        self.assertEqual(dv, TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.DECRYPT)
        self.assertIsInstance(dv, TPMA_OBJECT)

    def test_base_decode_friendly_int(self):
        dec = base_encdec()
        alg = int(TPM2_ALG.SHA256)
        dv = dec.decode(TPM2_ALG(), alg)
        self.assertEqual(dv, TPM2_ALG.SHA256)
        self.assertIsInstance(dv, TPM2_ALG)

    def test_base_decode_int(self):
        dec = base_encdec()
        i = 1234
        dv = dec.decode(int(), i)
        self.assertEqual(dv, 1234)
        self.assertIsInstance(dv, int)

    def test_base_decode_simple_tpm2b(self):
        dec = base_encdec()
        hstr = "01020304"
        dv = dec.decode(TPM2B_DIGEST(), hstr)
        self.assertEqual(dv.buffer, b"\x01\x02\x03\x04")
        self.assertEqual(dv.size, 4)
        self.assertIsInstance(dv, TPM2B_DIGEST)

    def test_base_decode_complex_tpm2b(self):
        dec = base_encdec()
        points = {"x": "01", "y": "02"}
        dv = dec.decode(TPM2B_ECC_POINT(), points)
        self.assertEqual(dv.point.x, b"\x01")
        self.assertEqual(dv.point.y, b"\x02")
        self.assertIsInstance(dv, TPM2B_ECC_POINT)

    def test_base_decode_tpml(self):
        dec = base_encdec()
        cmds = (int(TPM2_CC.Create), int(TPM2_CC.CreatePrimary))
        dv = dec.decode(TPML_CC(), cmds)
        self.assertEqual(len(dv), 2)
        self.assertIsInstance(dv, TPML_CC)
        self.assertEqual(dv[0], TPM2_CC.Create)
        self.assertEqual(dv[1], TPM2_CC.CreatePrimary)
        self.assertIsInstance(dv[0], TPM2_CC)
        self.assertIsInstance(dv[1], TPM2_CC)

    def test_base_decode_struct(self):
        dec = base_encdec()
        templ = {"type": TPM2_ALG.RSA, "parameters": {"exponent": 1234, "keyBits": 1}}
        dv = dec.decode(TPMT_PUBLIC_PARMS(), templ)
        self.assertIsInstance(dv, TPMT_PUBLIC_PARMS)
        self.assertEqual(dv.type, TPM2_ALG.RSA)
        self.assertEqual(dv.parameters.rsaDetail.exponent, 1234)
        self.assertEqual(dv.parameters.rsaDetail.keyBits, 1)

    def test_base_decode_pcrselect(self):
        dec = base_encdec()
        sel = {"pcrSelect": [8, 15]}
        dv = dec.decode(TPMS_PCR_SELECT(), sel)
        self.assertEqual(dv.sizeofSelect, 2)
        self.assertEqual(bytes(dv.pcrSelect), b"\x00\x81\x00\x00")

    def test_base_decode_strict(self):
        points = {"x": "01", "y": "02", "z": "03"}
        decoder = base_encdec(strict=True)
        with self.assertRaises(ValueError) as e:
            decoder.decode(TPMS_ECC_POINT(), points)
        self.assertEqual(str(e.exception), "unknown field(s) z in source")

    def test_base_decode_case_insensitive(self):
        points = {"X": "01", "Y": "02"}
        dec = base_encdec(case_insensitive=True)
        dv = dec.decode(TPMS_ECC_POINT(), points)
        self.assertEqual(dv.x, b"\x01")
        self.assertEqual(dv.y, b"\x02")

    def test_base_decode_bad(self):
        dec = base_encdec()
        with self.assertRaises(TypeError) as e:
            dec.decode(TPMU_KDF_SCHEME(), {})
        self.assertEqual(str(e.exception), "tried to decode union TPMU_KDF_SCHEME")

        with self.assertRaises(TypeError) as e:
            dec.decode("", {})
        self.assertEqual(str(e.exception), "unable to decode value of type str")

    def test_base_bad_selector(self):
        enc = base_encdec()
        cap = TPMS_CAPABILITY_DATA(capability=TPM2_CAP.VENDOR_PROPERTY + 1)
        with self.assertRaises(ValueError) as e:
            enc.encode(cap)
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field data in TPMS_CAPABILITY_DATA",
        )

        att = TPMS_ATTEST(type=TPM2_ST.FU_MANIFEST + 1)
        with self.assertRaises(ValueError) as e:
            enc.encode(att)
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field attested in TPMS_ATTEST",
        )

        keyed = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.LAST + 1)
        with self.assertRaises(ValueError) as e:
            enc.encode(keyed)
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field details in TPMT_KEYEDHASH_SCHEME",
        )

        sig = TPMT_SIGNATURE(sigAlg=TPM2_ALG.LAST + 1)
        with self.assertRaises(ValueError) as e:
            enc.encode(sig)
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field signature in TPMT_SIGNATURE",
        )

        dec = base_encdec()
        with self.assertRaises(ValueError) as e:
            dec._get_by_selector(TPMT_PUBLIC(), "badfield")
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field badfield in TPMT_PUBLIC",
        )

        with self.assertRaises(ValueError) as e:
            dec._get_by_selector(TPMT_PUBLIC(type=TPM2_ALG.NULL), "unique")
        self.assertEqual(
            str(e.exception),
            "unable to find union selector for field unique in TPMT_PUBLIC",
        )

    def test_json_enc_int(self):
        enc = json_encdec()
        ev = enc.encode(1234)
        self.assertEqual(ev, 1234)

        ev = enc.encode(0x100000002)
        self.assertEqual(ev, [1, 2])

    def test_json_enc_friendly_int(self):
        enc = json_encdec()
        ev = enc.encode(TPM2_RH.OWNER)
        self.assertEqual(ev, "owner")

        ev = enc.encode(TPM2_ALG.LAST + 1)
        self.assertIsInstance(ev, int)
        self.assertEqual(ev, int(TPM2_ALG.LAST + 1))

        ev = enc.encode(TPM2_GENERATED.VALUE)
        self.assertEqual(ev, "value")

    def test_json_enc_friendly_intlist(self):
        enc = json_encdec()
        ev = enc.encode(TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.RESTRICTED)
        self.assertEqual(ev, {"userwithauth": 1, "restricted": 1})

        ev = enc.encode(TPMA_NV.AUTHREAD | TPM2_NT.COUNTER << TPMA_NV.TPM2_NT_SHIFT)
        self.assertEqual(ev, {"authread": 1, "nt": "counter"})

        ev = enc.encode(TPMA_CC.NV | 5 << TPMA_CC.CHANDLES_SHIFT | 1234)
        self.assertEqual(ev, {"nv": 1, "chandles": 5, "commandindex": 1234})

        ev = enc.encode(
            TPMA_LOCALITY.ZERO | TPMA_LOCALITY(5 << TPMA_LOCALITY.EXTENDED_SHIFT)
        )
        self.assertEqual(ev, {"zero": 1, "extended": 5})

    def test_json_dec_int(self):
        dec = json_encdec()
        dv = dec.decode(int(), 1234)
        self.assertEqual(dv, 1234)

        dv = dec.decode(int(), "0xAA")
        self.assertEqual(dv, 0xAA)

        dv = dec.decode(int(), [1, 2])
        self.assertEqual(dv, 0x100000002)

    def test_json_dec_friendly_int(self):
        dec = json_encdec()
        dv = dec.decode(TPM2_ALG(), "sha1")
        self.assertEqual(dv, TPM2_ALG.SHA1)

        dv = dec.decode(TPM2_ALG(), "0x4")
        self.assertEqual(dv, TPM2_ALG.SHA1)

        dv = dec.decode(TPM2_ALG(), int(TPM2_ALG.SHA1))
        self.assertEqual(dv, TPM2_ALG.SHA1)

    def test_json_dec_friendly_intlist(self):
        dec = json_encdec()
        dv = dec.decode(
            TPMA_OBJECT.RESTRICTED,
            {"userwithauth": 1, "restricted": 0, "sign_encrypt": 1},
        )
        self.assertEqual(dv, TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)

        dv = dec.decode(TPMA_OBJECT(), ["TPMA_OBJECT_RESTRICTED", "ADMINWITHPOLICY"])
        self.assertEqual(dv, TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.ADMINWITHPOLICY)

        dv = dec.decode(
            TPMA_OBJECT(), f"0x{TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT:x}"
        )
        self.assertEqual(dv, TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)

        dv = dec.decode(TPMA_NV(), {"written": "set", "nt": "counter"})
        self.assertEqual(dv, TPMA_NV.WRITTEN | TPM2_NT.COUNTER << TPMA_NV.TPM2_NT_SHIFT)

        dv = dec.decode(TPMA_CC(), {"v": 1, "commandindex": 1234, "chandles": 5})
        self.assertEqual(dv, TPMA_CC.V | 1234 | 5 << TPMA_CC.CHANDLES_SHIFT)

        dv = dec.decode(TPMA_LOCALITY(), {"one": 1, "extended": 5})
        self.assertEqual(dv, TPMA_LOCALITY(0xA0) | TPMA_LOCALITY.ONE)

    def test_json_dec_simple_tpm2b(self):
        dec = json_encdec()
        dv = dec.decode(TPM2B_DIGEST(), "01020304")
        self.assertEqual(dv, b"\x01\x02\x03\x04")

        dv = dec.decode(TPM2B_DIGEST(), "0xff")
        self.assertEqual(dv, b"\xFF")

        dv = dec.decode(TPM2B_DIGEST(), [1, 2, 3, 4])
        self.assertEqual(dv, b"\x01\x02\x03\x04")


class ToolsTest(TSS2_BaseTest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.has_tools = False
        if shutil.which("tpm2") and sys.version_info >= (3, 7):
            self.has_tools = True
            self.tools_version = self._get_tools_version()

    def run_tool(self, *tool_args, no_tcti=False):
        args = ("tpm2",) + tuple(tool_args)
        if not no_tcti:
            tcti = self.tpm.tcti_name_conf
            args = args + ("--tcti", tcti)
            su_args = ("tpm2", "startup", "--clear", "--tcti", tcti)
            res = subprocess.run(su_args, timeout=20, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(
                    f"tpm2 startup failed with {res.returncode}: {res.stderr}"
                )
        res = subprocess.run(args, timeout=20, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(
                f"{' '.join(args)} failed with {res.returncode}: {res.stderr}"
            )
        return res.stdout

    def _get_tools_version(self):
        out = self.run_tool("--version", no_tcti=True)
        kvps = out.split()
        kvp = [x for x in kvps if "version=" in x][0]
        return TSS2Version(kvp.split("=")[1].replace('"', ""))

    def test_tools_tpms_nv_public(self):
        self.maxDiff = None
        enc = tools_encdec()
        nvp = TPMS_NV_PUBLIC(
            nvIndex=0xFABC1234,
            nameAlg=TPM2_ALG.SHA1,
            attributes=TPMA_NV.POLICYWRITE | TPMA_NV.AUTHREAD,
            authPolicy=b"\x0a\x0b\x0c\x0d\x01\x02\x03\x04",
            dataSize=3,
        )
        ev = enc.encode(nvp)
        self.assertEqual(
            ev,
            {
                0xFABC1234: {
                    "name": "00047bbf13f835329dc6e1fedabc11f25a0cc3656ebc",
                    "hash algorithm": {"friendly": "sha1", "value": 0x4},
                    "attributes": {
                        "friendly": "policywrite|authread",
                        "value": 0x40008,
                    },
                    "size": 3,
                    "authorization policy": "0A0B0C0D01020304",
                },
            },
        )

    def test_tools_tpmt_public(self):
        self.maxDiff = None
        enc = tools_encdec()

        _, sympub = TPM2B_SENSITIVE.symcipher_from_secret(
            b"\xFA" * 32, seed=b"\x00" * 32
        )
        ev = enc.encode(sympub)
        self.assertEqual(
            ev,
            {
                "name-alg": {"value": "sha256", "raw": 0xB},
                "attributes": {"value": "userwithauth|decrypt|sign", "raw": 0x60040},
                "type": {"value": "symcipher", "raw": 0x25},
                "sym-alg": {"value": "aes", "raw": 0x6},
                "sym-mode": {"value": "cfb", "raw": 0x43},
                "sym-keybits": 256,
                "symcipher": "69fa9a376a9798e756d36172120be93b464ebaf76d200ab7502f9ec53a73182f",
            },
        )

        keyedscheme = TPMT_KEYEDHASH_SCHEME(
            scheme=TPM2_ALG.HMAC,
            details=TPMU_SCHEME_KEYEDHASH(
                hmac=TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA512),
            ),
        )
        _, keyedpub = TPM2B_SENSITIVE.keyedhash_from_secret(
            b"\xFA" * 32, scheme=keyedscheme, seed=b"\x00" * 32
        )
        ev = enc.encode(keyedpub)
        self.assertEqual(
            ev,
            {
                "name-alg": {"value": "sha256", "raw": 0xB},
                "attributes": {"value": "userwithauth|decrypt|sign", "raw": 0x60040},
                "type": {"value": "keyedhash", "raw": 0x8},
                "hash-alg": {"value": "sha512", "raw": 0xD},
            },
        )

        rsapub = TPM2B_PUBLIC.parse(
            "rsa2048:rsapss-sha256",
            authPolicy=b"\x0a\x0b\x0c\x0d",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
            ^ TPMA_OBJECT.DECRYPT,
        )
        rsapub.publicArea.unique.rsa = b"\xFF" * 256
        ev = enc.encode(rsapub)
        self.assertEqual(
            ev,
            {
                "name-alg": {"value": "sha256", "raw": 0xB},
                "attributes": {
                    "value": "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                    "raw": 0x40072,
                },
                "type": {"value": "rsa", "raw": 0x1},
                "exponent": 65537,
                "bits": 2048,
                "scheme": {"value": "rsapss", "raw": 0x16},
                "scheme-halg": {"value": "sha256", "raw": 0xB},
                "sym-alg": {"value": "aes", "raw": 0x6},
                "sym-mode": {"value": "cfb", "raw": 0x43},
                "sym-keybits": 128,
                "rsa": "ff" * 256,
                "authorization policy": "0a0b0c0d",
            },
        )

        eccpub = TPM2B_PUBLIC.parse(
            "ecc:ecdh:aes256cfb",
            objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
            ^ TPMA_OBJECT.DECRYPT,
        )
        eccpub.publicArea.unique.ecc.x = b"x" * 32
        eccpub.publicArea.unique.ecc.y = b"y" * 32
        ev = enc.encode(eccpub)
        self.assertEqual(
            ev,
            {
                "name-alg": {"value": "sha256", "raw": 0xB},
                "attributes": {
                    "value": "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                    "raw": 0x40072,
                },
                "type": {"value": "ecc", "raw": 0x23},
                "curve-id": {"value": "nist_p256", "raw": 0x3},
                "kdfa-alg": {"value": None, "raw": 0x10},
                "kdfa-halg": {"value": "error", "raw": 0x0},
                "scheme": {"value": "ecdh", "raw": 0x19},
                "scheme-halg": {"value": "sha256", "raw": 0xB},
                "sym-alg": {"value": "aes", "raw": 0x6},
                "sym-mode": {"value": "cfb", "raw": 0x43},
                "sym-keybits": 256,
                "x": "78" * 32,
                "y": "79" * 32,
            },
        )

    def test_tools_tpml_alg_property(self):
        enc = tools_encdec()
        al = TPML_ALG_PROPERTY(
            [
                TPMS_ALG_PROPERTY(
                    alg=TPM2_ALG.RSA,
                    algProperties=(TPMA_ALGORITHM.RESERVED1_MASK & 0xA << 4)
                    | TPMA_ALGORITHM.ASYMMETRIC
                    | TPMA_ALGORITHM.OBJECT,
                ),
            ]
        )

        ev = enc.encode(al)
        self.assertEqual(
            ev,
            {
                "rsa": {
                    "value": 0x1,
                    "asymmetric": 1,
                    "symmetric": 0,
                    "hash": 0,
                    "object": 1,
                    "reserved": 0xA,
                    "signing": 0,
                    "encrypting": 0,
                    "method": 0,
                },
            },
        )

    def test_tools_tpml_cca(self):
        self.maxDiff = None
        enc = tools_encdec()
        cl = TPML_CCA(
            [
                (TPMA_CC.COMMANDINDEX_MASK & TPM2_CC.HMAC)
                | (TPMA_CC.RESERVED1_MASK & (0x3B << 16))
                | (TPMA_CC.CHANDLES_MASK & (0x3 << TPMA_CC.CHANDLES_SHIFT))
                | TPMA_CC.V
                | (TPMA_CC.RES_MASK & (0x3 << TPMA_CC.RES_SHIFT))
            ]
        )

        ev = enc.encode(cl)
        self.assertEqual(
            ev,
            {
                "TPM2_CC_HMAC": {
                    "value": 0xE63B0155,
                    "commandIndex": 0x155,
                    "reserved1": 0x3B,
                    "nv": 0,
                    "extensive": 0,
                    "flushed": 0,
                    "cHandles": 0x3,
                    "rHandle": 0,
                    "V": 1,
                    "Res": 0x3,
                },
            },
        )

    def test_tools_tpml_pcr_selection(self):
        enc = tools_encdec()
        pl = TPML_PCR_SELECTION(
            [
                TPMS_PCR_SELECTION.parse("sha1:0,2,4,22"),
                TPMS_PCR_SELECTION.parse("sha256:1,3,5,23"),
            ]
        )

        ev = enc.encode(pl)
        self.assertEqual(
            ev,
            {"selected-pcrs": [{"sha1": [0, 2, 4, 22]}, {"sha256": [1, 3, 5, 23],}]},
        )

    def test_tools_tpml_tagged_tpm_property(self):
        self.maxDiff = None
        enc = tools_encdec()
        pl = TPML_TAGGED_TPM_PROPERTY(
            [
                TPMS_TAGGED_PROPERTY(property=TPM2_PT.LEVEL, value=9001),
                TPMS_TAGGED_PROPERTY(
                    property=TPM2_PT.FAMILY_INDICATOR, value=0x332E3100
                ),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT.REVISION, value=455),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT.MANUFACTURER, value=0x54657374),
                TPMS_TAGGED_PROPERTY(
                    property=TPM2_PT.MODES, value=TPMA_MODES.FIPS_140_2
                ),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT_VENDOR.STRING_4, value=0),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT.PERMANENT, value=0xFFFFFFFF),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT.STARTUP_CLEAR, value=0xFFFFFFFF),
                TPMS_TAGGED_PROPERTY(property=TPM2_PT_NV.COUNTERS_AVAIL, value=9001),
            ],
        )
        ev = enc.encode(pl)
        self.assertEqual(
            ev,
            {
                "TPM2_PT_LEVEL": {"raw": 9001},
                "TPM2_PT_FAMILY_INDICATOR": {"raw": 0x332E3100, "value": "3.1"},
                "TPM2_PT_REVISION": {"raw": 0x1C7, "value": 4.55},
                "TPM2_PT_MANUFACTURER": {"raw": 0x54657374, "value": "Test"},
                "TPM2_PT_MODES": {"raw": 0x1, "value": "TPMA_MODES_FIPS_140_2"},
                "TPM2_PT_VENDOR_STRING_4": {"raw": 0x0, "value": ""},
                "TPM2_PT_PERMANENT": {
                    "ownerAuthSet": 1,
                    "endorsementAuthSet": 1,
                    "lockoutAuthSet": 1,
                    "reserved1": 1,
                    "disableClear": 1,
                    "inLockout": 1,
                    "tpmGeneratedEPS": 1,
                    "reserved2": 1,
                },
                "TPM2_PT_STARTUP_CLEAR": {
                    "phEnable": 1,
                    "shEnable": 1,
                    "ehEnable": 1,
                    "phEnableNV": 1,
                    "reserved1": 1,
                    "orderly": 1,
                },
                "TPM2_PT_NV_COUNTERS_AVAIL": 0x2329,
            },
        )

    def test_tools_tpml_ecc_curve(self):
        enc = tools_encdec()
        el = TPML_ECC_CURVE([TPM2_ECC.NIST_P521, TPM2_ECC.SM2_P256])

        ev = enc.encode(el)
        self.assertEqual(ev, {"TPM2_ECC_NIST_P521": 0x5, "TPM2_ECC_SM2_P256": 0x20})

    def test_tools_tpml_handle(self):
        enc = tools_encdec()
        hl = TPML_HANDLE([TPM2_RH.OWNER, 0x81000000, 0xF])

        ev = enc.encode(hl)
        self.assertEqual(ev, [0x40000001, 0x81000000, 0xF])

    def test_to_yaml(self):
        pl = TPML_PCR_SELECTION(
            [TPMS_PCR_SELECTION.parse("sha1:0"), TPMS_PCR_SELECTION.parse("sha256:1")]
        )
        yml = to_yaml(pl)
        self.assertEqual(yml, "selected-pcrs:\n- sha1:\n  - 0\n- sha256:\n  - 1\n")

    def test_tools_tpms_context(self):
        enc = tools_encdec()
        ch = "BADCC0DE000000014000000180000000000000000000031503300000000002A20020BD6A5850A4FDFFBB180601EADDACFC446562AD2763A68279E71891A7B8FDE23B027E6F2848DD84D5AD62FB282A6D5F9C108E67C1EA18581747E31A20C4FED2CD806F8A817A1A379C105BE24EBE639C695566D1488C00FE7E9249069B7ACFFCF34AA640B0C4F6D4818319A5A16CACE56F7AA5138732B7406C7ADCFEB4FBBA986A6B12186A75A192C02B7CF0F6C19C459E1EC4EBBA06893A6EF61005E3C92D598E55686F8B2796A46BEF95C88643C26FBD6E57A282588AF8A83D5976D938BFD5C6B50E1BDB27AAB87ADA4B4EEFEA4BDE98E7B53FD4A536A5B9B5578033F17B105DE4EB043A49B1427273E92C0607FCCEC14ADC584A2576AA55C0610F036394FED299E725E708BF7C4A130735A69C13C664137BB614B24E1914FD8F3182E0105B79A47C3C9D8E34D2BDAAAD87010F81499D731B2A83B33C963D12B4F9C9BD6420B6481B8FEC114C0A5B8B344D0D2E8AE5D612840E17A24507ACF6F1A2D457DE44D8613579992CC474CC79DED932397BA04844D2F748A243E6CE99F269D07673C67AD40D3D9C093F7D9DCEE7CACF8B1A72327AD935539DCB18A8876DBDD10A6AB7512A6372DEDCE90298042B53C9ABB0F573344906529DE4574215547754515906F76C5E6A515EDDF878FF7CE45A8B1B76CB54D7E68428A509145223AFAB285A06D39E8348BBDA04DBE78E38DEC01EB8B06E6A65603F3D4D3B79123E70F1CA8199712ACDF18B2FA71B199B12B8C6D8F1737CAA68A76BD8DA33B1735EB41AA62112006D0E28744D81D9437B8919F2E490969ED72470557288AE772440EC80BD3E48878889E0683C1DF3CA117BE0F68BC6197FE4483695C797F7A7369EAC7C357B62A0FC6C0DB3DFB56272DCD601B2D0F10911A2E8B91ADD8AC7127D7CB5EFE3C3E145FFB4A283541CEAAEFF0F15FAC1E2D4A66855B9D44BBB5B017463C02A517143D50000800000FF0022000BF6833B300E4908B4F760109BC1FBBD4A551FCEB7678057B50092F3ED1CEF872B0000000100580023000B00040060000000100018000B0003001000205EA29C688EA872D49AB05B876468EEC6B9EA994DA4EE5626C49DFA240E5160AE00205532E6FD5408C395D59C7067A9DF121BA95652FB0F6A1A3F8E8F07797A49F0DA"
        cb = unhexlify(ch)
        ctx = TPMS_CONTEXT.from_tools(cb)

        ev = enc.encode(ctx)
        self.assertEqual(
            ev,
            {
                "version": 1,
                "hierarchy": "owner",
                "handle": "0x80000000 (2147483648)",
                "sequence": 789,
                "contextBlob": {"size": 816},
            },
        )

    def test_tools_pcr_tuple(self):
        enc = tools_encdec()
        sels = TPML_PCR_SELECTION.parse("sha1:0,1,2,3+sha256:4,5,6,7")
        digs = TPML_DIGEST()
        for i in range(0, 4):
            digs[i] = TPM2B_DIGEST(i.to_bytes(1, "big") * 20)
            digs.count += 1
        for i in range(4, 8):
            digs[i] = TPM2B_DIGEST(i.to_bytes(1, "big") * 32)
            digs.count += 1

        ev = enc.encode((sels, digs))
        self.assertEqual(
            ev,
            {
                "sha1": {
                    0: 0,
                    1: 0x0101010101010101010101010101010101010101,
                    2: 0x0202020202020202020202020202020202020202,
                    3: 0x0303030303030303030303030303030303030303,
                },
                "sha256": {
                    4: 0x0404040404040404040404040404040404040404040404040404040404040404,
                    5: 0x0505050505050505050505050505050505050505050505050505050505050505,
                    6: 0x0606060606060606060606060606060606060606060606060606060606060606,
                    7: 0x0707070707070707070707070707070707070707070707070707070707070707,
                },
            },
        )

    def test_tools_pcr_tuples(self):
        enc = tools_encdec()
        tuples = [
            (TPML_PCR_SELECTION.parse("sha1:0"), TPML_DIGEST([b"\x00" * 20])),
            (TPML_PCR_SELECTION.parse("sha256:1"), TPML_DIGEST([b"\x01" * 32])),
        ]

        ev = enc.encode(tuples)
        self.assertEqual(
            ev,
            {
                "sha1": {0: 0},
                "sha256": {
                    1: 0x0101010101010101010101010101010101010101010101010101010101010101,
                },
            },
        )

    def test_tools_decode_tpml_handle(self):
        if not self.has_tools:
            self.skipTest("tools not in path")

        yml = self.run_tool("getcap", "handles-pcr")
        hl = from_yaml(yml, TPML_HANDLE())
        self.assertEqual(list(hl), list(range(0, 24)))

    def test_tools_decode_tpml_ecc_curve(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif not self.tpm.tcti_name_conf.startswith("swtpm"):
            self.skipTest("swtpm required")
        yml = self.run_tool("getcap", "ecc-curves")
        el = from_yaml(yml, TPML_ECC_CURVE())
        self.assertEqual(
            list(el),
            [
                TPM2_ECC.NIST_P192,
                TPM2_ECC.NIST_P224,
                TPM2_ECC.NIST_P256,
                TPM2_ECC.NIST_P384,
                TPM2_ECC.NIST_P521,
                TPM2_ECC.BN_P256,
                TPM2_ECC.BN_P638,
                TPM2_ECC.SM2_P256,
            ],
        )

    def test_tools_decode_tpml_alg_property(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif not self.tpm.tcti_name_conf.startswith("swtpm"):
            self.skipTest("swtpm required")
        yml = self.run_tool("getcap", "algorithms")
        al = from_yaml(yml, TPML_ALG_PROPERTY())
        self.assertEqual(al[0].alg, TPM2_ALG.RSA)
        self.assertEqual(
            al[0].algProperties, TPMA_ALGORITHM.ASYMMETRIC | TPMA_ALGORITHM.OBJECT
        )
        self.assertEqual(al[2].alg, TPM2_ALG.SHA1)
        self.assertEqual(al[2].algProperties, TPMA_ALGORITHM.HASH)

    def test_tools_decode_tmpl_pcr_selection(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        yml = self.run_tool("getcap", "pcrs")
        pl = from_yaml(yml, TPML_PCR_SELECTION())
        self.assertEqual(pl[0].hash, TPM2_ALG.SHA1)
        self.assertEqual(pl[0].sizeofSelect, 3)
        self.assertEqual(bytes(pl[0].pcrSelect), b"\xFF\xFF\xFF\x00")
        self.assertEqual(pl[1].hash, TPM2_ALG.SHA256)
        self.assertEqual(pl[1].sizeofSelect, 3)
        self.assertEqual(bytes(pl[1].pcrSelect), b"\xFF\xFF\xFF\x00")

    def test_tools_decode_tpml_cca(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        yml = self.run_tool("getcap", "commands")
        cl = from_yaml(yml, TPML_CCA())
        self.assertEqual(cl[0], TPMA_CC(0x440011F))
        self.assertEqual(cl[1], TPMA_CC(0x4400120))

    def test_tools_decode_tpml_tagged_tpm_property(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif not self.tpm.tcti_name_conf.startswith("swtpm"):
            self.skipTest("swtpm required")

        fixedyml = self.run_tool("getcap", "properties-fixed")
        fl = from_yaml(fixedyml, TPML_TAGGED_TPM_PROPERTY())
        self.assertEqual(fl[0].property, TPM2_PT.FAMILY_INDICATOR)
        self.assertEqual(fl[0].value, 0x322E3000)
        self.assertEqual(fl[1].property, TPM2_PT.LEVEL)
        self.assertEqual(fl[1].value, 0)
        self.assertEqual(fl[2].property, TPM2_PT.REVISION)
        self.assertEqual(fl[2].value, 0xA4)

        varyml = self.run_tool("getcap", "properties-variable")
        vl = from_yaml(varyml, TPML_TAGGED_TPM_PROPERTY())
        self.assertEqual(vl[0].property, TPM2_PT.PERMANENT)
        self.assertEqual(vl[0].value, TPMA_PERMANENT.TPMGENERATEDEPS)
        self.assertEqual(vl[1].property, TPM2_PT.STARTUP_CLEAR)
        self.assertEqual(
            vl[1].value,
            TPMA_STARTUP.CLEAR_PHENABLE
            | TPMA_STARTUP.CLEAR_SHENABLE
            | TPMA_STARTUP.CLEAR_EHENABLE
            | TPMA_STARTUP.CLEAR_PHENABLENV
            | TPMA_STARTUP.CLEAR_ORDERLY,
        )
        self.assertEqual(vl[2].property, TPM2_PT_HR.NV_INDEX)
        self.assertEqual(vl[2].value, 0)

    def test_tools_decode_tpms_nv_public(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        self.run_tool("nvdefine", "-s", "8", "-g", "sha256", "0x1800004")
        yml = self.run_tool("nvreadpublic")
        nvp = from_yaml(yml, TPMS_NV_PUBLIC())
        self.assertEqual(nvp.nvIndex, 0x1800004)
        self.assertEqual(nvp.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(nvp.attributes, 0x60006)
        self.assertEqual(nvp.dataSize, 8)

    def test_tools_decode_tpmt_public(self):
        if not self.has_tools:
            self.skipTest("tools not in path")

        rsayml = self.run_tool(
            "createprimary",
            "-G",
            "rsa2048:rsapss-sha256:null",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
        )
        rsapub = from_yaml(rsayml, TPMT_PUBLIC())
        self.assertEqual(rsapub.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(rsapub.objectAttributes, TPMA_OBJECT(0x40072))
        self.assertEqual(rsapub.type, TPM2_ALG.RSA)
        self.assertEqual(rsapub.parameters.rsaDetail.exponent, 0)
        self.assertEqual(rsapub.parameters.rsaDetail.keyBits, 2048)
        self.assertEqual(rsapub.parameters.rsaDetail.scheme.scheme, TPM2_ALG.RSAPSS)
        self.assertEqual(
            rsapub.parameters.rsaDetail.scheme.details.anySig.hashAlg, TPM2_ALG.SHA256
        )
        self.assertEqual(rsapub.parameters.rsaDetail.symmetric.algorithm, TPM2_ALG.NULL)
        self.assertEqual(rsapub.parameters.rsaDetail.symmetric.mode.sym, TPM2_ALG.ERROR)
        self.assertEqual(rsapub.parameters.rsaDetail.symmetric.keyBits.sym, 0)
        self.assertEqual(len(rsapub.unique.rsa), 256)

        eccyml = self.run_tool(
            "createprimary",
            "-G",
            "ecc:ecdaa-sha256:null",
            "-g",
            "sha1",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
        )
        eccpub = from_yaml(eccyml, TPMT_PUBLIC())
        self.assertEqual(eccpub.nameAlg, TPM2_ALG.SHA1)
        self.assertEqual(eccpub.objectAttributes, TPMA_OBJECT(0x40072))
        self.assertEqual(eccpub.type, TPM2_ALG.ECC)
        self.assertEqual(eccpub.parameters.eccDetail.curveID, TPM2_ECC.NIST_P256)
        self.assertEqual(eccpub.parameters.eccDetail.kdf.scheme, TPM2_ALG.NULL)
        self.assertEqual(
            eccpub.parameters.eccDetail.kdf.details.mgf1.hashAlg, TPM2_ALG.ERROR
        )
        self.assertEqual(eccpub.parameters.eccDetail.scheme.scheme, TPM2_ALG.ECDAA)
        self.assertEqual(
            eccpub.parameters.eccDetail.scheme.details.ecdaa.hashAlg, TPM2_ALG.SHA256
        )
        self.assertEqual(eccpub.parameters.eccDetail.scheme.details.ecdaa.count, 0)
        self.assertEqual(eccpub.parameters.eccDetail.symmetric.algorithm, TPM2_ALG.NULL)
        self.assertEqual(eccpub.parameters.eccDetail.symmetric.mode.sym, TPM2_ALG.ERROR)
        self.assertEqual(eccpub.parameters.eccDetail.symmetric.keyBits.sym, 0)
        self.assertEqual(len(eccpub.unique.ecc.x), 32)
        self.assertEqual(len(eccpub.unique.ecc.y), 32)

        keyedyml = self.run_tool(
            "createprimary",
            "-G",
            "hmac",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
        )
        keyedpub = from_yaml(keyedyml, TPMT_PUBLIC())
        self.assertEqual(keyedpub.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(keyedpub.objectAttributes, TPMA_OBJECT(0x40072))
        self.assertEqual(keyedpub.type, TPM2_ALG.KEYEDHASH)
        self.assertEqual(
            keyedpub.parameters.keyedHashDetail.scheme.scheme, TPM2_ALG.HMAC
        )
        self.assertEqual(
            keyedpub.parameters.keyedHashDetail.scheme.details.hmac.hashAlg,
            TPM2_ALG.SHA256,
        )
        self.assertEqual(len(keyedpub.unique.keyedHash), 32)
        self.run_tool("flushcontext", "-t")

        symyml = self.run_tool(
            "createprimary",
            "-G",
            "aes128cfb",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt",
        )
        sympub = from_yaml(symyml, TPMT_PUBLIC())
        self.assertEqual(sympub.type, TPM2_ALG.SYMCIPHER)
        self.assertEqual(sympub.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(sympub.objectAttributes, TPMA_OBJECT(0x20072))
        self.assertEqual(sympub.parameters.symDetail.sym.algorithm, TPM2_ALG.AES)
        self.assertEqual(sympub.parameters.symDetail.sym.mode.sym, TPM2_ALG.CFB)
        self.assertEqual(sympub.parameters.symDetail.sym.keyBits.sym, 128)
        self.assertEqual(len(sympub.unique.sym), 32)

    def test_tools_decode_pcr_tuples(self):
        self.maxDiff = None

        if not self.has_tools:
            self.skipTest("tools not in path")
        yml = self.run_tool("pcrread", "sha1:0,1,2,3,4,5,6,7,8+sha256:0")

        pcrs = from_yaml(yml, (TPML_PCR_SELECTION(), TPML_DIGEST()))
        self.assertEqual(len(pcrs), 2)
        self.assertEqual(pcrs[0][0].count, 1)
        self.assertEqual(pcrs[0][0][0].hash, TPM2_ALG.SHA1)
        self.assertEqual(pcrs[0][0][0].sizeofSelect, 1)
        self.assertEqual(len(pcrs[0][1]), 8)
        self.assertEqual(pcrs[0][1][0], b"\00" * 20)
        self.assertEqual(pcrs[0][1][1], b"\00" * 20)
        self.assertEqual(pcrs[0][1][2], b"\00" * 20)
        self.assertEqual(pcrs[0][1][3], b"\00" * 20)
        self.assertEqual(pcrs[0][1][4], b"\00" * 20)
        self.assertEqual(pcrs[0][1][5], b"\00" * 20)
        self.assertEqual(pcrs[0][1][6], b"\00" * 20)
        self.assertEqual(pcrs[0][1][7], b"\00" * 20)
        self.assertEqual(pcrs[1][0][0].hash, TPM2_ALG.SHA1)
        self.assertEqual(pcrs[1][0][0].sizeofSelect, 2)
        self.assertEqual(pcrs[1][0][1].hash, TPM2_ALG.SHA256)
        self.assertEqual(pcrs[1][0][1].sizeofSelect, 1)
        self.assertEqual(len(pcrs[1][1]), 2)
        self.assertEqual(pcrs[1][1][0], b"\00" * 20)
        self.assertEqual(pcrs[1][1][1], b"\00" * 32)

    def test_tools_tpma_session(self):
        enc = tools_encdec()
        ev = enc.encode(TPMA_SESSION.AUDIT | TPMA_SESSION.ENCRYPT)
        self.assertEqual(ev, {"Session-Attributes": "encrypt|audit"})

    def test_tools_decode_tpma_session(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        session_path = os.path.join(
            self.tpm.working_dir.name, "test_decode_tpma_session.ctx"
        )
        self.run_tool("startauthsession", "-S", session_path)
        self.run_tool(
            "sessionconfig", "--enable-decrypt", "--enable-audit", session_path,
        )
        yml = self.run_tool("sessionconfig", session_path)

        attrs = from_yaml(yml, TPMA_SESSION())
        self.assertEqual(
            attrs,
            TPMA_SESSION.DECRYPT | TPMA_SESSION.CONTINUESESSION | TPMA_SESSION.AUDIT,
        )

    def test_tools_tpml_digest_values(self):
        enc = tools_encdec()
        vals = TPML_DIGEST_VALUES(
            [
                TPMT_HA(hashAlg=TPM2_ALG.SHA1, digest=TPMU_HA(sha512=b"\x01" * 20)),
                TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha512=b"\x02" * 32)),
            ]
        )
        ev = enc.encode(vals)
        self.assertEqual(
            ev, {"sha1": "01" * 20, "sha256": "02" * 32},
        )

    def test_tools_decode_tpml_digest_values(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        data_path = os.path.join(self.tpm.working_dir.name, "eventdata")
        with open(data_path, "w") as f:
            f.write("falafel")
        yml = self.run_tool("pcrevent", "8", data_path)
        dv = from_yaml(yml, TPML_DIGEST_VALUES())
        self.assertEqual(len(dv), 4)
        self.assertEqual(dv[0].hashAlg, TPM2_ALG.SHA1)
        self.assertEqual(
            bytes(dv[0]), unhexlify("49477eefc260670d35faf60f885f7f0bb9bd6f6e")
        )
        self.assertEqual(dv[1].hashAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            bytes(dv[1]),
            unhexlify(
                "b0a1499eaed4edb2b4893dfa2ac2a4ba26c7db0e64d1c8dcc1ae092a70ff1538"
            ),
        )
        self.assertEqual(dv[2].hashAlg, TPM2_ALG.SHA384)
        self.assertEqual(
            bytes(dv[2]),
            unhexlify(
                "69a3a8e70031302b15978079ca7780db5d36d6f8b637838c876ae3fa6464f0359d8ab2f0d4dc8d56ed8ecf4661249cc4"
            ),
        )
        self.assertEqual(dv[3].hashAlg, TPM2_ALG.SHA512)
        self.assertEqual(
            bytes(dv[3]),
            unhexlify(
                "d9a6a0417a7461907ccdcfe53cda43c8a4e816b00190bae1b3608c209542c91b3239968a5b5620c3c5748849964a561e5a871bb62f556883ae60e11bc1f52942"
            ),
        )

    def test_tools_tpml_alg(self):
        enc = tools_encdec()
        vals = TPML_ALG([TPM2_ALG.SHA1, TPM2_ALG.RSA])
        ev = enc.encode(vals)
        self.assertEqual(ev, {"remaining": "sha1 rsa"})

    def test_tools_decode_tpml_alg(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif not self.tpm.tcti_name_conf.startswith("swtpm"):
            self.skipTest("swtpm required")
        self.run_tool("incrementalselftest", "rsa", "ecc")
        yml = self.run_tool("incrementalselftest")
        al = from_yaml(yml, TPML_ALG())
        self.assertIn(TPM2_ALG.RSAPSS, al)
        self.assertIn(TPM2_ALG.RSASSA, al)

    def test_tools_tpm2b_name(self):
        enc = tools_encdec()
        name = TPM2_ALG.SHA1.to_bytes(2, "big") + b"\xFF" * 20
        name2b = TPM2B_NAME(name)
        hn = hexlify(name).decode("ascii")
        ev = enc.encode(name2b)
        self.assertEqual(ev, {"name": hn})

    def test_tools_decode_tpm2b_name(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        key = ec.generate_private_key(ec.SECP256R1).public_key()
        kb = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_path = os.path.join(self.tpm.working_dir.name, "external.key")
        ctx_path = os.path.join(self.tpm.working_dir.name, "external.ctx")
        with open(key_path, "wb") as f:
            f.write(kb)
        yml = self.run_tool("loadexternal", "-G", "ecc", "-u", key_path, "-c", ctx_path)
        name = from_yaml(yml, TPM2B_NAME())
        self.assertEqual(len(name), 34)
        self.assertEqual(name[0:2], b"\x00\x0b")

    def test_decode_int(self):
        v = from_yaml("1234", int(0))
        self.assertEqual(v, 1234)

    def test_decode_int_nt(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif self.tools_version < TSS2Version("5.3"):
            self.skipTest("tpm2-tools version 5.3 or later required")

        self.run_tool("nvdefine", "0x01000000", "-a", "authwrite|authread|nt=bits")
        self.run_tool("nvsetbits", "0x01000000", "-i", "0x4000000000000001")
        yml = self.run_tool("nvread", "0x01000000", "--print-yaml", "-s", "8")
        v = from_yaml(yml, int(0))
        self.assertEqual(v, 0x4000000000000001)

        self.run_tool("nvdefine", "0x01200000", "-a", "authwrite|authread|nt=counter")
        self.run_tool("nvincrement", "0x01200000")
        yml = self.run_tool("nvread", "0x01200000", "--print-yaml", "-s", "8")
        v = from_yaml(yml, int(0))
        self.assertEqual(v, 1)

    def test_decode_nt_extend(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif self.tools_version < TSS2Version("5.3"):
            self.skipTest("tpm2-tools version 5.3 or later required")

        self.run_tool(
            "nvdefine",
            "0x01000000",
            "-g",
            "sha256",
            "-a",
            "authwrite|authread|nt=extend",
        )
        extend_path = os.path.join(self.tpm.working_dir.name, "extend_data")
        with open(extend_path, "wb") as f:
            f.write(b"falafel")
        self.run_tool("nvextend", "0x01000000", "-i", extend_path)
        yml = self.run_tool("nvread", "0x01000000", "--print-yaml", "-s", "32")
        v = from_yaml(yml, TPMT_HA())
        self.assertEqual(v.hashAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            bytes(v),
            b"\xc5r\x87#\xa3\xbbW\x91m\xb9\xe5\xde\xa9\x01\tLc\xa9`Y\x8a\x8a)\xfe'z\xee_j\x8e\xe7\xce",
        )

    def test_decode_nt_pin(self):
        if not self.has_tools:
            self.skipTest("tools not in path")
        elif self.tools_version < TSS2Version("5.3"):
            self.skipTest("tpm2-tools version 5.3 or later required")

        self.run_tool(
            "nvdefine",
            "0x01000000",
            "-C",
            "o",
            "-a",
            "ownerwrite|ownerread|nt=pinfail|no_da",
        )
        pfail = TPMS_NV_PIN_COUNTER_PARAMETERS(pinCount=1234, pinLimit=5678)
        fb = pfail.marshal()
        fail_path = os.path.join(self.tpm.working_dir.name, "pinfail_data")
        with open(fail_path, "wb") as f:
            f.write(fb)
        self.run_tool("nvwrite", "0x01000000", "-C", "o", "-i", fail_path)
        yml = self.run_tool(
            "nvread", "0x01000000", "-C", "o", "--print-yaml", "-s", "8"
        )
        print(yml)
        v = from_yaml(yml, TPMS_NV_PIN_COUNTER_PARAMETERS())
        self.assertEqual(v.pinCount, 1234)
        self.assertEqual(v.pinLimit, 5678)

        self.run_tool(
            "nvdefine",
            "0x01200000",
            "-C",
            "o",
            "-a",
            "ownerwrite|ownerread|nt=pinpass|no_da",
        )
        ppass = TPMS_NV_PIN_COUNTER_PARAMETERS(pinCount=8765, pinLimit=4321)
        pb = ppass.marshal()
        pass_path = os.path.join(self.tpm.working_dir.name, "pinpass_data")
        with open(pass_path, "wb") as f:
            f.write(pb)
        self.run_tool("nvwrite", "0x01200000", "-C", "o", "-i", pass_path)
        yml = self.run_tool(
            "nvread", "0x01200000", "-C", "o", "--print-yaml", "-s", "8"
        )
        v = from_yaml(yml, TPMS_NV_PIN_COUNTER_PARAMETERS())
        self.assertEqual(v.pinCount, 8765)
        self.assertEqual(v.pinLimit, 4321)

    def test_tools_nt_pin(self):
        enc = tools_encdec()
        pin = TPMS_NV_PIN_COUNTER_PARAMETERS(pinCount=1234, pinLimit=5678)
        ev = enc.encode(pin)
        self.assertEqual(ev, {"pinCount": 1234, "pinLimit": 5678})

    def test_tools_unsupported(self):
        dlyml = """
        - FF00
        """
        with self.assertRaises(ValueError) as e:
            from_yaml(dlyml, TPML_DIGEST())
        self.assertEqual(str(e.exception), "unsupported list TPML_DIGEST")

        tsyml = """
        sensitiveType: test
        """
        with self.assertRaises(ValueError) as e:
            from_yaml(tsyml, TPMT_SENSITIVE())
        self.assertEqual(str(e.exception), "unsupported structure TPMT_SENSITIVE")

        with self.assertRaises(ValueError) as e:
            to_yaml(TPML_DIGEST())
        self.assertEqual(str(e.exception), "unsupported list TPML_DIGEST")

        with self.assertRaises(ValueError) as e:
            to_yaml(TPMT_SENSITIVE())
        self.assertEqual(str(e.exception), "unsupported structure TPMT_SENSITIVE")


if __name__ == "__main__":
    unittest.main()
