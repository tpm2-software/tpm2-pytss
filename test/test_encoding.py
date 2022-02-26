#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import unittest

from tpm2_pytss import *
from tpm2_pytss.encoding import (
    base_encdec,
    json_encdec,
)


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
            dv = decoder.decode(TPMS_ECC_POINT(), points)
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
            dv = dec.decode(TPMU_KDF_SCHEME(), {})
        self.assertEqual(str(e.exception), "tried to decode union TPMU_KDF_SCHEME")

        with self.assertRaises(TypeError) as e:
            dv = dec.decode("", {})
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


if __name__ == "__main__":
    unittest.main()
