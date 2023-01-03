#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import unittest
import textwrap
import json
from tpm2_pytss import *
from tpm2_pytss.internal.utils import _lib_version_atleast
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from .TSS2_BaseTest import TSS2_EsapiTest

if not _lib_version_atleast("tss2-policy", "4.0.0"):
    raise unittest.SkipTest("tss2-policy not installed or version is less then 4.0.0")


def lowercase_dict(src):
    if not isinstance(src, dict):
        return src
    dest = dict()
    for k, v in src.items():
        if isinstance(v, str):
            lv = v.lower()
            dest[k] = lv
        elif isinstance(v, dict):
            dest[k] = lowercase_dict(v)
        elif isinstance(v, list):
            l = list()
            for e in v:
                if isinstance(e, str):
                    le = e.lower()
                elif isinstance(e, dict):
                    le = lowercase_dict(e)
                else:
                    le = e
                l.append(le)
            dest[k] = l
        else:
            dest[k] = v
    return dest


class TestPolicy(TSS2_EsapiTest):
    def test_password_policy(self):
        pol = {
            "description": "this is a policy",
            "policy": [{"type": "POLICYPASSWORD"}],
        }
        calcpol = {
            "description": "this is a policy",
            "policyDigests": [
                {
                    "digest": "af6038c78c5c962d37127e319124e3a8dc582e9b",
                    "hashAlg": "SHA1",
                }
            ],
            "policy": [
                {
                    "type": "POLICYPASSWORD",
                    "policyDigests": [
                        {
                            "digest": "af6038c78c5c962d37127e319124e3a8dc582e9b",
                            "hashAlg": "SHA1",
                        }
                    ],
                }
            ],
        }

        polstr = json.dumps(pol).encode()
        with policy(polstr, TPM2_ALG.SHA1) as p:
            desc = p.description
            polp = p.policy
            halg = p.hash_alg
            p.calculate()
            dig = p.get_calculated_digest()
            cjb = p.get_calculated_json()
        self.assertEqual(desc, b"this is a policy")
        self.assertEqual(polp, polstr)
        self.assertEqual(halg, TPM2_ALG.SHA1)
        self.assertEqual(
            dig.buffer, b"\xaf`8\xc7\x8c\\\x96-7\x12~1\x91$\xe3\xa8\xdcX.\x9b"
        )
        cj = json.loads(cjb)
        self.assertEqual(lowercase_dict(cj), lowercase_dict(calcpol))

    def test_password_policy_execute(self):
        pol = {
            "description": "this is a policy",
            "policy": [{"type": "POLICYPASSWORD"}],
        }
        polstr = json.dumps(pol).encode()
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA1,
        )
        with policy(polstr, TPM2_ALG.SHA1) as p:
            p.execute(self.ectx, session)
        dig2b = self.ectx.policy_get_digest(session)
        self.assertEqual(
            dig2b.buffer, b"\xaf`8\xc7\x8c\\\x96-7\x12~1\x91$\xe3\xa8\xdcX.\x9b"
        )

    def test_callbacks(self):
        pol = {
            "description": "this is a policy",
            "policy": [{"type": "POLICYPASSWORD"}],
        }
        polstr = json.dumps(pol)

        def test():
            pass

        p = policy(polstr, TPM2_ALG.SHA256)
        p.set_callback(policy_cb_types.CALC_PCR, test)
        cb = p._get_callback(policy_cb_types.CALC_PCR)
        self.assertEqual(cb, test)

        p.set_callback(policy_cb_types.CALC_PCR, None)
        cb = p._get_callback(policy_cb_types.CALC_PCR)
        self.assertEqual(cb, None)

        with self.assertRaises(ValueError) as e:
            p.set_callback(1234, test)
        self.assertEqual(str(e.exception), "unsupported callback type 1234")

    def test_calc_pcr_callback(self):
        pol = {
            "description": "this is a pcr policy",
            "policy": [{"type": "pcr", "currentPCRs": [0, 8]}],
        }
        calc_pol = {
            "description": "this is a pcr policy",
            "policyDigests": [
                {
                    "hashAlg": "SHA256",
                    "digest": "e5a442791c55f8c4a3e391385e170a24c75add21bc2c140fc4f4a2628810f13f",
                }
            ],
            "policy": [
                {
                    "type": "POLICYPCR",
                    "policyDigests": [
                        {
                            "hashAlg": "SHA256",
                            "digest": "e5a442791c55f8c4a3e391385e170a24c75add21bc2c140fc4f4a2628810f13f",
                        }
                    ],
                    "pcrs": [
                        {"pcr": 0, "hashAlg": "SHA256", "digest": "00" * 32},
                        {"pcr": 8, "hashAlg": "SHA256", "digest": "08" * 32},
                    ],
                }
            ],
        }
        polstr = json.dumps(pol).encode()
        cb_called = False
        cb_selection = TSS2_POLICY_PCR_SELECTION()

        def pcr_cb(selection):
            nonlocal cb_called
            nonlocal cb_selection
            cb_called = True
            cb_selection = selection
            sel = TPMS_PCR_SELECTION(
                hash=TPM2_ALG.SHA256,
                sizeofSelect=selection.selections.pcr_select.sizeofSelect,
                pcrSelect=selection.selections.pcr_select.pcrSelect,
            )
            out_sel = TPML_PCR_SELECTION((sel,))
            digests = list()
            selb = bytes(sel.pcrSelect[0 : sel.sizeofSelect])
            seli = int.from_bytes(reversed(selb), "big")
            for i in range(0, sel.sizeofSelect * 8):
                if (1 << i) & seli:
                    dig = TPM2B_DIGEST(bytes([i]) * 32)
                    digests.append(dig)
            out_dig = TPML_DIGEST(digests)
            return (out_sel, out_dig)

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PCR, pcr_cb)
            p.calculate()
            cjb = p.get_calculated_json()

        cj = json.loads(cjb)
        self.assertTrue(cb_called)
        self.assertIsInstance(cb_selection, TSS2_POLICY_PCR_SELECTION)
        self.assertEqual(cb_selection.type, TSS2_POLICY_PCR_SELECTOR.PCR_SELECT)
        self.assertEqual(cb_selection.selections.pcr_select.sizeofSelect, 3)
        self.assertEqual(
            bytes(cb_selection.selections.pcr_select.pcrSelect), b"\x01\x01\x00\x00"
        )
        self.assertEqual(lowercase_dict(cj), lowercase_dict(calc_pol))

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PCR, bad_cb)
            p.calculate()
        self.assertEqual(str(e.exception), "callback exception")

    def test_calc_name_callback(self):
        pol = {
            "description": "this is a name policy",
            "policy": [{"type": "namehash", "namePaths": ["path1", "path2", "path3"]}],
        }
        calc_pol = {
            "description": "this is a name policy",
            "policyDigests": [
                {
                    "hashAlg": "SHA256",
                    "digest": "7334f60c505d0007343c33e697cadce69ca56cebe7870ad68c65534b1eee5fa6",
                }
            ],
            "policy": [
                {
                    "type": "POLICYNAMEHASH",
                    "policyDigests": [
                        {
                            "hashAlg": "SHA256",
                            "digest": "7334f60c505d0007343c33e697cadce69ca56cebe7870ad68c65534b1eee5fa6",
                        }
                    ],
                    "nameHash": "15c6f51a0c7d0b68942d62b4eaf59b3240e819a566361b0b052f46e4422051d8",
                }
            ],
        }
        polstr = json.dumps(pol).encode()

        cb_called = 0
        cb_names = list()

        def name_cb(name):
            nonlocal cb_called
            nonlocal cb_names
            cb_called += 1
            cb_names.append(name)
            return TPM2B_NAME(b"\x00\x0b" + bytes([cb_called]) * 32)

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NAME, name_cb)
            p.calculate()
            cjb = p.get_calculated_json()

        cj = json.loads(cjb)
        self.assertEqual(cb_called, 3)
        self.assertEqual(cb_names, [b"path1", b"path2", b"path3"])
        self.assertEqual(lowercase_dict(cj), lowercase_dict(calc_pol))

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NAME, bad_cb)
            p.calculate()
        self.assertEqual(str(e.exception), "callback exception")

    def test_calc_public_callback(self):
        pol = {
            "description": "this is a public policy",
            "policy": [{"type": "duplicationselect", "newParentPath": "parent_path"}],
        }
        calc_pol = {
            "description": "this is a public policy",
            "policyDigests": [
                {
                    "hashAlg": "SHA256",
                    "digest": "fd6ba57a0029f93e76628ecffe78911df5c93cc24e5d53e06472e0c3dd116e76",
                }
            ],
            "policy": [
                {
                    "type": "POLICYDUPLICATIONSELECT",
                    "policyDigests": [
                        {
                            "hashAlg": "SHA256",
                            "digest": "fd6ba57a0029f93e76628ecffe78911df5c93cc24e5d53e06472e0c3dd116e76",
                        }
                    ],
                    "objectName": "",
                    "newParentName": "000b6e59ef657bca3b9624088244e6f67ab28d7843a8f53df58e37c67b0df7152f44",
                    "includeObject": "NO",
                },
            ],
        }
        polstr = json.dumps(pol).encode()

        cb_path = None

        def public_cb(path):
            nonlocal cb_path
            cb_path = path
            return TPMT_PUBLIC.parse("rsa2048")

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PUBLIC, public_cb)
            p.calculate()
            cjb = p.get_calculated_json()

        cj = json.loads(cjb)
        self.assertEqual(cb_path, b"parent_path")
        self.assertEqual(lowercase_dict(cj), lowercase_dict(calc_pol))

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PUBLIC, bad_cb)
            p.calculate()
        self.assertEqual(str(e.exception), "callback exception")

    def test_calc_nvpublic_callback(self):
        pol = {
            "description": "this is a nvpublic policy",
            "policy": [{"type": "authorizenv", "nvPath": "nv_path"}],
        }
        calc_pol = {
            "description": "this is a nvpublic policy",
            "policyDigests": [
                {
                    "hashAlg": "SHA256",
                    "digest": "31e4f72a6ca046ca0dc4a8765b400ac01fe76502b9b820e7927a50b253624494",
                }
            ],
            "policy": [
                {
                    "type": "POLICYAUTHORIZENV",
                    "policyDigests": [
                        {
                            "hashAlg": "SHA256",
                            "digest": "31e4f72a6ca046ca0dc4a8765b400ac01fe76502b9b820e7927a50b253624494",
                        }
                    ],
                    "nvPublic": {
                        "nvIndex": 0x1000000,
                        "nameAlg": "SHA256",
                        "attributes": {
                            "PPWRITE": 0,
                            "OWNERWRITE": 0,
                            "AUTHWRITE": 0,
                            "POLICYWRITE": 0,
                            "POLICY_DELETE": 0,
                            "WRITELOCKED": 0,
                            "WRITEALL": 0,
                            "WRITEDEFINE": 0,
                            "WRITE_STCLEAR": 0,
                            "GLOBALLOCK": 0,
                            "PPREAD": 0,
                            "OWNERREAD": 0,
                            "AUTHREAD": 0,
                            "POLICYREAD": 0,
                            "NO_DA": 0,
                            "ORDERLY": 0,
                            "CLEAR_STCLEAR": 0,
                            "READLOCKED": 0,
                            "WRITTEN": 1,
                            "PLATFORMCREATE": 0,
                            "READ_STCLEAR": 0,
                            "TPM2_NT": "ORDINARY",
                        },
                        "authPolicy": "",
                        "dataSize": 0,
                    },
                },
            ],
        }
        polstr = json.dumps(pol).encode()

        cb_nvpath = None
        cb_nvindex = None

        def nvpublic_cb(path, index):
            nonlocal cb_nvpath, cb_nvindex
            cb_nvpath = path
            cb_nvindex = index
            nvp = TPMS_NV_PUBLIC(nvIndex=0x1000000, nameAlg=TPM2_ALG.SHA256)
            return nvp

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NVPUBLIC, nvpublic_cb)
            p.calculate()
            cjb = p.get_calculated_json()

        cj = json.loads(cjb)
        self.assertEqual(cb_nvpath, b"nv_path")
        self.assertEqual(cb_nvindex, 0)
        self.assertIsInstance(cb_nvindex, TPM2_HANDLE)
        self.assertEqual(lowercase_dict(cj), lowercase_dict(calc_pol))

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NVPUBLIC, bad_cb)
            p.calculate()
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_auth_callback(self):
        pol = {
            "description": "this is an auth policy",
            "policy": [{"type": "nv", "nvIndex": "0x1000000", "operandB": "00"}],
        }
        polstr = json.dumps(pol).encode()
        nvp = TPMS_NV_PUBLIC(
            nvIndex=0x1000000,
            nameAlg=TPM2_ALG.SHA256,
            attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
            dataSize=1,
        )
        nvh = self.ectx.nv_define_space(None, TPM2B_NV_PUBLIC(nvp))
        self.ectx.nv_write(nvh, b"\x00")

        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA1,
        )

        def nvpublic_cb(path, index):
            nonlocal nvp
            if index == 0x1000000:
                return nvp
            return None

        cb_name = TPM2B_NAME()

        def auth_cb(name):
            nonlocal cb_name
            nonlocal nvh
            cb_name = name
            return (nvh, nvh, ESYS_TR.PASSWORD)

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NVPUBLIC, nvpublic_cb)
            p.set_callback(policy_cb_types.EXEC_AUTH, auth_cb)
            p.execute(self.ectx, session)

        dig2b = self.ectx.policy_get_digest(session)
        self.assertEqual(
            cb_name,
            b"\x00\x0b\x11\xf2\x07J\x1e\xcde\xf8T\x1cU\x15T\x80\xbb<\xdb\x83\xbf\x10\xffy\x8b\x9bB\\n\xa8E\xbe\xeaP",
        )
        self.assertEqual(
            dig2b, b"Ad\x9eq\xa0!\xc0\xef\xe8v\x053\x97x\xbd;\xfa\x9c\x14|"
        )

        def bad_cb(name):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_NVPUBLIC, nvpublic_cb)
            p.set_callback(policy_cb_types.EXEC_AUTH, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_polsel_callback(self):
        pol = {
            "description": "this is a polsel policy",
            "policy": [
                {
                    "type": "or",
                    "branches": [
                        {
                            "name": "branch1",
                            "description": "branch1 description",
                            "policy": [{"type": "password"}],
                        },
                        {
                            "name": "branch2",
                            "description": "branch2 description",
                            "policy": [{"type": "locality", "locality": ["zero",]}],
                        },
                    ],
                },
            ],
        }
        polstr = json.dumps(pol).encode()
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )
        cb_auth_object = ""
        cb_branches = None

        def polsel_cb(auth_object, branches):
            nonlocal cb_auth_object
            nonlocal cb_branches
            cb_auth_object = auth_object
            cb_branches = branches
            return len(branches) - 1

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLSEL, polsel_cb)
            p.execute(self.ectx, session)

        dig2b = self.ectx.policy_get_digest(session)
        self.assertEqual(cb_auth_object, None)
        self.assertEqual(cb_branches, [b"branch1", b"branch2"])
        self.assertEqual(
            dig2b,
            b"8\x17\xfa\x84\x98\xf9\xf6\xa0s\xaa\xc5\x91r\x0b\xc4\xea\xdf3\xd6\xdb#\xd5\n\x05\x12\xd7\x8a\x84\xb5\xa3\xb2\xa1",
        )

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLSEL, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_sign_callback(self):
        private_key = textwrap.dedent(
            """
            -----BEGIN PRIVATE KEY-----
            MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEVTBTAgEBBBgBJYQqvoPfXctJixFL
            lAzRLQaAFBHOoQyhNAMyAATAjqP6LEx2q1p5aUSAfSwIpr0NijnvyLfWtluYrqCJ
            sI7HNirP/FKiz8pIY3FAD18=
            -----END PRIVATE KEY-----
            """
        ).encode("ascii")
        public_key = textwrap.dedent(
            """
            -----BEGIN PUBLIC KEY-----
            MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEwI6j+ixMdqtaeWlEgH0sCKa9DYo5
            78i31rZbmK6gibCOxzYqz/xSos/KSGNxQA9f
            -----END PUBLIC KEY-----
            """
        ).encode("ascii")
        pol = {
            "description": "this is a sign policy",
            "policy": [
                {
                    "type": "signed",
                    "publicKeyHint": "test key",
                    "keyPEM": public_key.decode(),
                },
            ],
        }
        polstr = json.dumps(pol).encode()
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )
        pkey = load_pem_private_key(private_key, password=None)
        cb_pem = None
        cb_key_hint = None
        cb_hash_alg = None
        cb_buf = None

        def sign_cb(pem, key_hint, hash_alg, buf):
            nonlocal pkey, cb_pem, cb_key_hint, cb_hash_alg, cb_buf
            cb_pem = pem
            cb_key_hint = key_hint
            cb_hash_alg = hash_alg
            cb_buf = buf
            sig = pkey.sign(buf, ec.ECDSA(hashes.SHA256()))
            return sig

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_SIGN, sign_cb)
            p.execute(self.ectx, session)

        dig2b = self.ectx.policy_get_digest(session)
        self.assertEqual(cb_pem, public_key.lstrip(b"\n"))
        self.assertEqual(cb_key_hint, b"test key")
        self.assertEqual(cb_hash_alg, TPM2_ALG.SHA256)
        self.assertEqual(
            dig2b,
            b"\xc6L!\x81v\x893\xee\x14)^eYi/\xa3\x88\xa6}\xbf\xf1\x86\x99\x90\x9e\x10fg99\xecL",
        )

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_SIGN, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_polauth_callback(self):
        private_key = textwrap.dedent(
            """
            -----BEGIN PRIVATE KEY-----
            MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEVTBTAgEBBBgBJYQqvoPfXctJixFL
            lAzRLQaAFBHOoQyhNAMyAATAjqP6LEx2q1p5aUSAfSwIpr0NijnvyLfWtluYrqCJ
            sI7HNirP/FKiz8pIY3FAD18=
            -----END PRIVATE KEY-----
            """
        ).encode("ascii")
        public_key = textwrap.dedent(
            """
            -----BEGIN PUBLIC KEY-----
            MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEwI6j+ixMdqtaeWlEgH0sCKa9DYo5
            78i31rZbmK6gibCOxzYqz/xSos/KSGNxQA9f
            -----END PUBLIC KEY-----
            """
        ).encode("ascii")
        pol = {
            "description": "this is a polauth policy",
            "policy": [
                {
                    "type": "authorize",
                    "keyPEM": public_key.decode(),
                    "approvedPolicy": "01" * 32,
                    "policyRef": "02" * 32,
                },
            ],
        }
        polstr = json.dumps(pol).encode()
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.TRIAL,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )
        pkey = load_pem_private_key(private_key, password=None)
        cb_hash_alg = None
        cb_digest = None
        cb_policyref = None

        def polauth_cb(key_public, hash_alg, digest, policy_ref):
            nonlocal pkey, cb_hash_alg, cb_digest, cb_policyref
            cb_hash_alg = hash_alg
            cb_digest = digest
            cb_policyref = policy_ref
            buf = bytes(digest) + bytes(policy_ref)
            sig = pkey.sign(buf, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(sig)
            rlen = int(r.bit_length() / 8) + (r.bit_length() % 8 > 0)
            slen = int(s.bit_length() / 8) + (s.bit_length() % 8 > 0)
            rb = r.to_bytes(rlen, "big")
            sb = s.to_bytes(slen, "big")
            tpm_sig = TPMT_SIGNATURE(
                sigAlg=TPM2_ALG.ECDSA,
                signature=TPMU_SIGNATURE(
                    ecdsa=TPMS_SIGNATURE_ECC(
                        hash=TPM2_ALG.SHA256, signatureR=rb, signatureS=sb,
                    )
                ),
            )
            return tpm_sig

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLAUTH, polauth_cb)
            p.execute(self.ectx, session)

        self.assertEqual(cb_hash_alg, TPM2_ALG.SHA256)
        self.assertEqual(cb_digest, b"\x01" * 32)
        self.assertEqual(cb_policyref, b"\x02" * 32)

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLAUTH, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_polauthnv_callback(self):
        pol = {
            "description": "this is a polauthnv policy",
            "policy": [
                {
                    "type": "authorizenv",
                    "nvPublic": {
                        "nvIndex": 0x1000000,
                        "nameAlg": "SHA256",
                        "attributes": {
                            "PPWRITE": 0,
                            "OWNERWRITE": 0,
                            "AUTHWRITE": 1,
                            "POLICYWRITE": 0,
                            "POLICY_DELETE": 0,
                            "WRITELOCKED": 0,
                            "WRITEALL": 0,
                            "WRITEDEFINE": 0,
                            "WRITE_STCLEAR": 0,
                            "GLOBALLOCK": 0,
                            "PPREAD": 0,
                            "OWNERREAD": 0,
                            "AUTHREAD": 1,
                            "POLICYREAD": 0,
                            "NO_DA": 0,
                            "ORDERLY": 0,
                            "CLEAR_STCLEAR": 0,
                            "READLOCKED": 0,
                            "WRITTEN": 1,
                            "PLATFORMCREATE": 0,
                            "READ_STCLEAR": 0,
                            "TPM2_NT": "ORDINARY",
                        },
                        "authPolicy": "",
                        "dataSize": 34,
                    },
                },
            ],
        }
        polstr = json.dumps(pol)
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )
        nvp = TPMS_NV_PUBLIC(
            nvIndex=0x1000000,
            nameAlg=TPM2_ALG.SHA256,
            attributes=TPMA_NV.AUTHWRITE | TPMA_NV.AUTHREAD,
            dataSize=34,
        )
        nvh = self.ectx.nv_define_space(None, TPM2B_NV_PUBLIC(nvp))
        self.ectx.nv_write(nvh, b"\x00\x0b" + b"\x00" * 32)

        cb_nv_public = None
        cb_hash_alg = None

        def polauthnv_cb(nv_public, hash_alg):
            nonlocal cb_nv_public, cb_hash_alg
            cb_nv_public = nv_public
            cb_hash_alg = hash_alg

        cb_name = None

        def auth_cb(name):
            nonlocal cb_name, nvh
            cb_name = name
            return (nvh, nvh, ESYS_TR.PASSWORD)

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLAUTHNV, polauthnv_cb)
            p.set_callback(policy_cb_types.EXEC_AUTH, auth_cb)
            p.execute(self.ectx, session)

        self.assertEqual(cb_nv_public.nvIndex, nvp.nvIndex)
        self.assertEqual(cb_nv_public.nameAlg, nvp.nameAlg)
        self.assertEqual(cb_nv_public.attributes, nvp.attributes | TPMA_NV.WRITTEN)
        self.assertEqual(cb_nv_public.dataSize, nvp.dataSize)
        self.assertEqual(cb_hash_alg, TPM2_ALG.SHA256)
        self.assertEqual(
            cb_name,
            b"\x00\x0bx\x7f\x8a\xa5&\xdbK\xf2L\x97\x8by\x92\x1f\xf4*\xae\xe6E\xa1\x15\xfb|\x05]\xed\xd4\x9f\xc3\xb5\xd1\xf6",
        )

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_AUTH, auth_cb)
            p.set_callback(policy_cb_types.EXEC_POLAUTHNV, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_poldup_callback(self):
        pol = {
            "description": "this is a poldup policy",
            "policy": [
                {"type": "duplicationselect", "newParentPath": "new parent path"},
            ],
        }
        polstr = json.dumps(pol)
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        cb_path = None

        def poldup_cb():
            return TPM2B_NAME(b"\x12" * 32)

        def public_cb(path):
            nonlocal cb_path
            cb_path = path
            return TPMT_PUBLIC.parse("rsa2048")

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PUBLIC, public_cb)
            p.set_callback(policy_cb_types.EXEC_POLDUP, poldup_cb)
            p.execute(self.ectx, session)
        dig2b = self.ectx.policy_get_digest(session)

        self.assertEqual(cb_path, b"new parent path")
        self.assertEqual(
            dig2b,
            b"\xfdk\xa5z\x00)\xf9>vb\x8e\xcf\xfex\x91\x1d\xf5\xc9<\xc2N]S\xe0dr\xe0\xc3\xdd\x11nv",
        )

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PUBLIC, public_cb)
            p.set_callback(policy_cb_types.EXEC_POLDUP, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")

    def test_exec_polaction_callback(self):
        pol = {
            "description": "this is a polaction policy",
            "policy": [{"type": "action", "action": "this is an action"}],
        }
        polstr = json.dumps(pol)
        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        cb_action = None

        def polaction_cb(action):
            nonlocal cb_action
            cb_action = action

        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLACTION, polaction_cb)
            p.execute(self.ectx, session)

        self.assertEqual(cb_action, b"this is an action")

        def bad_cb(*args):
            raise Exception("callback exception")

        with self.assertRaises(Exception) as e, policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLACTION, bad_cb)
            p.execute(self.ectx, session)
        self.assertEqual(str(e.exception), "callback exception")
