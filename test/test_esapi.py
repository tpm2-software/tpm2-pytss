#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import unittest
import gc

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_EsapiTest


class TestEsys(TSS2_EsapiTest):
    def test_get_random(self):
        r = self.ectx.get_random(5)
        self.assertEqual(len(r), 5)

        with self.assertRaises(TypeError):
            self.ectx.get_random("foo")

        with self.assertRaises(TypeError):
            self.ectx.get_random(5, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.get_random(5, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.get_random(5, session3=56.7)

    def test_create_primary(self):
        inSensitive = TPM2B_SENSITIVE_CREATE()
        inPublic = TPM2B_PUBLIC()
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        inPublic.publicArea.type = TPM2_ALG.ECC
        inPublic.publicArea.nameAlg = TPM2_ALG.SHA1
        inPublic.publicArea.objectAttributes = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )

        inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDSA
        inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = (
            TPM2_ALG.SHA256
        )
        inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
        inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC.NIST_P256

        handle, public, creation_data, digest, ticket = self.ectx.create_primary(
            inSensitive, inPublic, ESYS_TR.OWNER, outsideInfo, creationPCR,
        )
        self.assertNotEqual(handle, 0)
        self.assertEqual(type(public), TPM2B_PUBLIC)
        self.assertEqual(type(creation_data), TPM2B_CREATION_DATA)
        self.assertEqual(type(digest), TPM2B_DIGEST)
        self.assertEqual(type(ticket), TPMT_TK_CREATION)
        self.ectx.flush_context(handle)

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive,)
        self.assertNotEqual(handle, 0)
        self.ectx.flush_context(handle)

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)
        self.assertNotEqual(handle, 0)
        self.ectx.flush_context(handle)

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, "ecc256")
        self.assertNotEqual(handle, 0)
        self.ectx.flush_context(handle)

        handle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "ecc256", creation_pcr="sha256:4,6,7"
        )
        self.assertNotEqual(handle, 0)
        self.ectx.flush_context(handle)

        with self.assertRaises(TypeError):
            self.ectx.create_primary(
                TPM2B_DATA, inPublic, ESYS_TR.OWNER, outsideInfo, creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.create_primary(
                inSensitive,
                b"should not work",
                ESYS_TR.OWNER,
                outsideInfo,
                creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.create_primary(
                inSensitive, inPublic, object(), outsideInfo, creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.create_primary(
                inSensitive, inPublic, ESYS_TR.OWNER, object(), creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.create_primary(
                inSensitive, inPublic, ESYS_TR.OWNER, outsideInfo, TPM2B_SENSITIVE(),
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.create_primary(
                inSensitive, "ecc256", session1=object()
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.create_primary(
                inSensitive, "ecc256", session2=object()
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.create_primary(
                inSensitive, "ecc256", session3=object()
            )

    def test_create_primary_none(self):
        handle, _, _, _, _ = self.ectx.create_primary(None)
        self.assertNotEqual(handle, 0)

    def test_pcr_read(self):

        pcrsels = TPML_PCR_SELECTION.parse("sha1:3+sha256:all")
        _, _, digests, = self.ectx.pcr_read(pcrsels)

        self.assertEqual(len(digests[0]), 20)

        for d in digests[1:]:
            self.assertEqual(len(d), 32)

        with self.assertRaises(TypeError):
            self.ectx.pcr_read(TPML_AC_CAPABILITIES())

        with self.assertRaises(TypeError):
            self.ectx.pcr_read(pcrsels, session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.pcr_read(pcrsels, session2=56.7)

        with self.assertRaises(TypeError):
            self.ectx.pcr_read(pcrsels, session3=object())

    def test_plain_nv_define_write_read_undefine(self):

        nv_public = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=TPM2_HC.NV_INDEX_FIRST,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.parse("ownerread|ownerwrite|authread|authwrite"),
                dataSize=32,
            )
        )

        # No password NV index
        nv_index = self.ectx.nv_define_space(None, nv_public)
        self.ectx.nv_write(nv_index, b"hello world")

        value = self.ectx.nv_read(nv_index, 11)
        self.assertEqual(bytes(value), b"hello world")

        public, name = self.ectx.nv_read_public(nv_index)
        self.assertEqual(public.nvPublic.nvIndex, TPM2_HC.NV_INDEX_FIRST)
        self.assertEqual(public.nvPublic.nameAlg, TPM2_ALG.SHA256)
        self.assertEqual(
            public.nvPublic.attributes,
            TPMA_NV.parse("ownerread|ownerwrite|authread|authwrite|written"),
        )
        self.assertEqual(public.nvPublic.authPolicy.size, 0)
        self.assertEqual(public.nvPublic.dataSize, 32)
        # Algorithm id (UINT16) followed by SHA256 len of name bytes
        self.assertEqual(len(name), 2 + 32)

        n = str(name)
        self.assertEqual(len(n), 68)
        self.assertTrue(isinstance(n, str))

        self.ectx.nv_undefine_space(nv_index)

        with self.assertRaises(TSS2_Exception):
            public, name = self.ectx.nv_read_public(nv_index)

    def test_hierarchychangeauth(self):

        self.ectx.hierarchy_change_auth(ESYS_TR.OWNER, "passwd")

        # force esys to forget about the 'good' password
        self.ectx.tr_set_auth(ESYS_TR.OWNER, "badpasswd")

        with self.assertRaises(TSS2_Exception):
            self.ectx.hierarchy_change_auth(ESYS_TR.OWNER, "anotherpasswd")

    def test_fulltest_yes(self):
        self.ectx.self_test(True)

    def test_fulltest_no(self):
        self.ectx.self_test(False)

    def test_incremental_self_test(self):
        algs = TPML_ALG.parse("rsa,ecc,xor,aes,cbc")

        self.ectx.incremental_self_test(algs)

        self.ectx.incremental_self_test("rsa,ecc,xor,aes,cbc")

        with self.assertRaises(TypeError):
            self.ectx.incremental_self_test(None)
        with self.assertRaises(TypeError):
            self.ectx.incremental_self_test(object())

        with self.assertRaises(TypeError):
            self.ectx.incremental_self_test(session1=45.9)

        with self.assertRaises(TypeError):
            self.ectx.incremental_self_test(session2=object())

        with self.assertRaises(TypeError):
            self.ectx.incremental_self_test(session3=TPM2B_PUBLIC())

    def test_incremental_resume_test(self):
        algs = TPML_ALG.parse("rsa,ecc,xor,aes,cbc")

        self.ectx.incremental_self_test(algs)
        toDo, rc = self.ectx.get_test_result()
        self.assertEqual(type(toDo), TPM2B_MAX_BUFFER)
        self.assertEqual(rc, TPM2_RC.SUCCESS)

        with self.assertRaises(TypeError):
            self.ectx.get_test_result(session1=45.7)

        with self.assertRaises(TypeError):
            self.ectx.get_test_result(session2=TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.get_test_result(session3=object())

    def test_hmac_session(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        hmac_session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.HMAC,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )
        self.assertTrue(hmac_session)
        self.ectx.hierarchy_change_auth(ESYS_TR.OWNER, "passwd", session1=hmac_session)

        # force esys to forget about the 'good' password
        self.ectx.tr_set_auth(ESYS_TR.OWNER, "badpasswd")

        with self.assertRaises(TSS2_Exception):
            self.ectx.hierarchy_change_auth(
                ESYS_TR.OWNER, "anotherpasswd", session1=hmac_session
            )

        # test some bad params
        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                object, ESYS_TR.NONE, TPM2_SE.HMAC, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, object(), TPM2_SE.HMAC, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(ValueError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, ESYS_TR.NONE, 8745635, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, ESYS_TR.NONE, object(), sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, ESYS_TR.NONE, TPM2_SE.HMAC, 42, TPM2_ALG.SHA256
            )

        with self.assertRaises(ValueError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, ESYS_TR.NONE, TPM2_SE.HMAC, sym, 8395847
            )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE, ESYS_TR.NONE, TPM2_SE.HMAC, sym, TPM2B_SYM_KEY()
            )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                ESYS_TR.NONE,
                ESYS_TR.NONE,
                TPM2_SE.HMAC,
                sym,
                TPM2_ALG.SHA256,
                TPM2B_PUBLIC(),
            )

    def test_start_auth_session_enckey(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=handle,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.trsess_set_attributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.get_random(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_start_auth_session_enckey_bindkey(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=handle,
            bind=handle,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.trsess_set_attributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.get_random(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_tr_sess_set_attributes(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=handle,
            bind=handle,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.trsess_set_attributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        with self.assertRaises(TypeError):
            self.ectx.trsess_set_attributes(
                object(), (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
            )

        with self.assertRaises(TypeError):
            self.ectx.trsess_set_attributes(session, 67.5)

        with self.assertRaises(TypeError):
            self.ectx.trsess_set_attributes(session, 1, 75.6)

    def test_start_auth_session_noncecaller(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=handle,
            bind=handle,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
            nonce_caller=TPM2B_NONCE(b"thisisthirtytwocharslastichecked"),
        )

        self.ectx.trsess_set_attributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.get_random(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_start_auth_session_noncecaller_bad(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        with self.assertRaises(TypeError):
            self.ectx.start_auth_session(
                tpm_key=ESYS_TR.NONE,
                bind=ESYS_TR.NONE,
                session_type=TPM2_SE.HMAC,
                symmetric=sym,
                auth_hash=TPM2_ALG.SHA256,
                nonce_caller=object(),
            )

    def test_create(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        alg = "rsa2048"
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg))
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic, outsideInfo
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic, creation_pcr=creationPCR
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle,
            childInSensitive,
            childInPublic,
            creation_pcr="sha256:1,2,3,4,5",
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        with self.assertRaises(TypeError):
            self.ectx.create(
                34.945, childInSensitive, childInPublic, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.create(
                parentHandle, object(), childInPublic, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.create(
                parentHandle, childInSensitive, 56, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.create(
                parentHandle, childInSensitive, childInPublic, None, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.create(
                parentHandle, childInSensitive, childInPublic, outsideInfo, object
            )

    def test_create_none(self):

        parentHandle = self.ectx.create_primary(None)[0]
        priv, pub = self.ectx.create(parentHandle, None)[0:2]
        self.assertEqual(type(pub), TPM2B_PUBLIC)
        self.assertEqual(type(priv), TPM2B_PRIVATE)

    def test_load(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.create(parentHandle, childInSensitive)

        childHandle = self.ectx.load(parentHandle, priv, pub)
        self.assertTrue(childHandle)

        with self.assertRaises(TypeError):
            self.ectx.load(42.5, priv, pub)

        with self.assertRaises(TypeError):
            self.ectx.load(parentHandle, TPM2B_DATA(), pub)

        with self.assertRaises(TypeError):
            self.ectx.load(parentHandle, priv, object())

    def test_readpublic(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.create(parentHandle, childInSensitive)

        childHandle = self.ectx.load(parentHandle, priv, pub)

        pubdata, name, qname = self.ectx.read_public(childHandle)
        self.assertTrue(
            isinstance(pubdata, TPM2B_PUBLIC),
            f"Expected TPM2B_PUBLIC, got: {type(pubdata)}",
        )
        self.assertTrue(
            isinstance(name, TPM2B_NAME), f"Expected TPM2B_NAME, got: {type(name)}"
        )
        self.assertTrue(
            isinstance(qname, TPM2B_NAME), f"Expected TPM2B_NAME, got: {type(qname)}"
        )

        self.assertTrue(pubdata.publicArea.type, TPM2_ALG.RSA)
        self.assertTrue(pubdata.publicArea.nameAlg, TPM2_ALG.SHA256)
        self.assertTrue(name.size, 32)
        self.assertTrue(qname.size, 32)

        with self.assertRaises(TypeError):
            self.ectx.read_public(object())

        with self.assertRaises(TypeError):
            self.ectx.read_public(childHandle, session1=object)

        with self.assertRaises(TypeError):
            self.ectx.read_public(childHandle, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.read_public(childHandle, session3=42.5)

    def test_make_credential(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        alg = "rsa2048"
        attrs = (
            TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.load(parentHandle, priv, pub)

        primaryKeyName = self.ectx.read_public(parentHandle)[1]

        credential = TPM2B_DIGEST("this is my credential")

        # this can be done without a key as in tpm2-tools project, but for simpplicity
        # use the TPM command, which uses the PUBLIC portion of the object and thus
        # needs no auth.
        credentialBlob, secret = self.ectx.make_credential(
            childHandle, credential, primaryKeyName
        )
        self.assertEqual(type(credentialBlob), TPM2B_ID_OBJECT)
        self.assertEqual(type(secret), TPM2B_ENCRYPTED_SECRET)

        credentialBlob, secret = self.ectx.make_credential(
            childHandle, "this is my credential", bytes(primaryKeyName)
        )
        self.assertEqual(type(credentialBlob), TPM2B_ID_OBJECT)
        self.assertEqual(type(secret), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.make_credential(42.5, credential, primaryKeyName)

        with self.assertRaises(TypeError):
            self.ectx.make_credential(childHandle, object(), primaryKeyName)

        with self.assertRaises(TypeError):
            self.ectx.make_credential(childHandle, credential, object())

        with self.assertRaises(TypeError):
            self.ectx.make_credential(
                childHandle, credential, primaryKeyName, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.make_credential(
                childHandle, credential, primaryKeyName, session2=54.6
            )

        with self.assertRaises(TypeError):
            self.ectx.make_credential(
                childHandle, credential, primaryKeyName, session3=object()
            )

    def test_activate_credential(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        alg = "rsa2048"
        attrs = (
            TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.load(parentHandle, priv, pub)

        primaryKeyName = self.ectx.read_public(parentHandle)[1]

        credential = TPM2B_DIGEST("this is my credential")

        # this can be done without a key as in tpm2-tools project, but for simpplicity
        # use the TPM command, which uses the PUBLIC portion of the object and thus
        # needs no auth.
        credentialBlob, secret = self.ectx.make_credential(
            childHandle, credential, primaryKeyName
        )

        self.ectx.tr_set_auth(childHandle, "childpassword")

        certInfo = self.ectx.activate_credential(
            parentHandle, childHandle, credentialBlob, secret
        )
        self.assertEqual(bytes(certInfo), b"this is my credential")

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(object(), childHandle, credentialBlob, secret)

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(parentHandle, 76.4, credentialBlob, secret)

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(
                parentHandle, childHandle, TPM2B_PUBLIC(), secret
            )

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(
                parentHandle, childHandle, credentialBlob, object()
            )

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(
                parentHandle, childHandle, credentialBlob, secret, session1="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(
                parentHandle, childHandle, credentialBlob, secret, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.activate_credential(
                parentHandle, childHandle, credentialBlob, secret, session3=65.4
            )

    def test_unseal(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        attrs = (
            TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.FIXEDPARENT | TPMA_OBJECT.FIXEDTPM
        )

        templ = TPMT_PUBLIC(
            type=TPM2_ALG.KEYEDHASH, objectAttributes=attrs, nameAlg=TPM2_ALG.SHA256
        )
        templ.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
        templ.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG.SHA256
        childInPublic = TPM2B_PUBLIC(templ)

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            # TODO make sure this works without the buffer, and for other SIMPLE TPM2B types
            TPMS_SENSITIVE_CREATE(
                userAuth=TPM2B_AUTH("childpassword"),
                data=TPM2B_SENSITIVE_DATA(b"sealedsecret"),
            )
        )

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.load(parentHandle, priv, pub)

        self.ectx.tr_set_auth(childHandle, "childpassword")

        secret = self.ectx.unseal(childHandle)
        self.assertEqual(bytes(secret), b"sealedsecret")

        with self.assertRaises(TypeError):
            self.ectx.unseal(45.2)

        with self.assertRaises(TypeError):
            self.ectx.unseal(childHandle, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.unseal(childHandle, session2=67.4)

        with self.assertRaises(TypeError):
            self.ectx.unseal(childHandle, session3="bar")

    def test_object_change_auth(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        alg = "rsa2048"
        attrs = (
            TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.load(parentHandle, priv, pub)

        # force an error
        self.ectx.tr_set_auth(childHandle, "BADchildpassword")

        with self.assertRaises(TSS2_Exception):
            self.ectx.object_change_auth(childHandle, parentHandle, "newauth")

        self.ectx.tr_set_auth(childHandle, "childpassword")

        self.ectx.object_change_auth(childHandle, parentHandle, TPM2B_AUTH("newauth"))

        self.ectx.object_change_auth(childHandle, parentHandle, b"anotherauth")

        self.ectx.object_change_auth(childHandle, parentHandle, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.object_change_auth("bad", parentHandle, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.object_change_auth(childHandle, 56.7, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.object_change_auth(childHandle, parentHandle, object())

    def test_createloaded(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, priv, pub = self.ectx.create_loaded(
            parentHandle, childInSensitive, childInPublic
        )
        self.assertNotEqual(childHandle, 0)
        self.assertEqual(type(priv), TPM2B_PRIVATE)
        self.assertEqual(type(pub), TPM2B_PUBLIC)

        childHandle, priv, pub = self.ectx.create_loaded(parentHandle, childInSensitive)
        self.assertNotEqual(childHandle, 0)
        self.assertEqual(type(priv), TPM2B_PRIVATE)
        self.assertEqual(type(pub), TPM2B_PUBLIC)

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(65.4, childInSensitive, childInPublic)

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(parentHandle, "1223", childInPublic)

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(parentHandle, childInSensitive, object())

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(parentHandle, childInSensitive, session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(parentHandle, childInSensitive, session2=b"baz")

        with self.assertRaises(TypeError):
            self.ectx.create_loaded(parentHandle, childInSensitive, session3=object())

    def test_createloaded_none(self):

        parentHandle = self.ectx.create_primary(None)[0]

        childHandle = self.ectx.create_loaded(parentHandle, None)[0]
        self.assertNotEqual(childHandle, 0)

    def test_rsa_enc_dec(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, _, _ = self.ectx.create_loaded(
            parentHandle, childInSensitive, childInPublic
        )

        message = TPM2B_PUBLIC_KEY_RSA("hello world")
        scheme = TPMT_RSA_DECRYPT(scheme=TPM2_ALG.RSAES)
        outData = self.ectx.rsa_encrypt(childHandle, message, scheme)

        message2 = self.ectx.rsa_decrypt(childHandle, outData, scheme)

        self.assertEqual(bytes(message), bytes(message2))

        outData = self.ectx.rsa_encrypt(childHandle, "hello world", scheme)

        message2 = self.ectx.rsa_decrypt(childHandle, outData, scheme)

        self.assertEqual(bytes(message), bytes(message2))

        # negative test rsa_encrypt
        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(45.6, message, scheme)

        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(childHandle, TPM2B_PUBLIC(), scheme)

        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(childHandle, message, "foo")

        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(childHandle, message, scheme, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(childHandle, message, scheme, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.rsa_encrypt(childHandle, message, scheme, session3=52.6)

        # negative test rsa_decrypt
        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(56.2, outData, scheme)

        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(childHandle, object(), scheme)

        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(childHandle, outData, TPM2_ALG.RSAES)

        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(childHandle, outData, scheme, session1=67.9)

        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(childHandle, outData, scheme, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.rsa_decrypt(childHandle, outData, scheme, session3=object())

    def test_rsa_enc_dec_with_label(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, _, _ = self.ectx.create_loaded(
            parentHandle, childInSensitive, childInPublic
        )

        message = TPM2B_PUBLIC_KEY_RSA("hello world")
        scheme = TPMT_RSA_DECRYPT(scheme=TPM2_ALG.RSAES)
        outData = self.ectx.rsa_encrypt(
            childHandle, message, scheme, label=b"my label\0"
        )

        message2 = self.ectx.rsa_decrypt(
            childHandle, outData, scheme, label=b"my label\0"
        )

        self.assertEqual(bytes(message), bytes(message2))

    def test_ecdh_key_gen(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()

        parentHandle, _, _, _, _ = self.ectx.create_primary(
            inSensitive, "ecc256:aes128cfb"
        )

        zPoint, pubPoint = self.ectx.ecdh_key_gen(parentHandle)
        self.assertNotEqual(zPoint, None)
        self.assertNotEqual(pubPoint, None)

        with self.assertRaises(TypeError):
            self.ectx.ecdh_key_gen(56.8)

        with self.assertRaises(TypeError):
            self.ectx.ecdh_key_gen(parentHandle, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.ecdh_key_gen(parentHandle, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ecdh_key_gen(parentHandle, session3=45.6)

    def test_ecdh_z_gen(self):

        alg = "ecc256:ecdh"
        attrs = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        parentHandle, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        inPoint = TPM2B_ECC_POINT(
            TPMS_ECC_POINT(
                x=binascii.unhexlify(
                    "25db1f8bbcfabc31f8176acbb2f840a3b6a5d340659d37eed9fd5247f514d598"
                ),
                y=binascii.unhexlify(
                    "ed623e3dd20908cf583c814bbf657e08ab9f40ffea51da21298ce24deb344ccc"
                ),
            )
        )

        outPoint = self.ectx.ecdh_zgen(parentHandle, inPoint)
        self.assertEqual(type(outPoint), TPM2B_ECC_POINT)

        with self.assertRaises(TypeError):
            self.ectx.ecdh_zgen(object(), inPoint)

        with self.assertRaises(TypeError):
            self.ectx.ecdh_zgen(parentHandle, "boo")

        with self.assertRaises(TypeError):
            self.ectx.ecdh_zgen(parentHandle, inPoint, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.ecdh_zgen(parentHandle, inPoint, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ecdh_zgen(parentHandle, inPoint, session3=89.6)

    def test_ecc_parameters(self):

        params = self.ectx.ecc_parameters(TPM2_ECC_CURVE.NIST_P256)
        self.assertEqual(type(params), TPMS_ALGORITHM_DETAIL_ECC)

        with self.assertRaises(ValueError):
            self.ectx.ecc_parameters(42)

        with self.assertRaises(TypeError):
            self.ectx.ecc_parameters(TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.ecc_parameters(TPM2_ECC_CURVE.NIST_P256, session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.ecc_parameters(TPM2_ECC_CURVE.NIST_P256, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ecc_parameters(TPM2_ECC_CURVE.NIST_P256, session3=TPM2B_DATA())

    def test_z_gen_2_phase(self):

        alg = "ecc256:ecdh-sha256"
        attrs = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.DECRYPT
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        eccHandle, outPublic, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        curveId = TPM2_ECC.NIST_P256

        Q, counter = self.ectx.ec_ephemeral(curveId)

        inQsB = TPM2B_ECC_POINT(outPublic.publicArea.unique.ecc)
        inQeB = Q
        Z1, Z2 = self.ectx.zgen_2_phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter)
        self.assertEqual(type(Z1), TPM2B_ECC_POINT)
        self.assertEqual(type(Z2), TPM2B_ECC_POINT)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(42.5, inQsB, inQeB, TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(eccHandle, "hello", inQeB, TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(eccHandle, inQsB, object(), TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(eccHandle, inQsB, inQeB, object(), counter)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, "baz")

        with self.assertRaises(ValueError):
            self.ectx.zgen_2_phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, 2 ** 18)

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session2="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.zgen_2_phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session3=45.5
            )

    def test_encrypt_decrypt(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()
        parentHandle = self.ectx.create_primary(inSensitive, "ecc")[0]

        inPublic = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(alg="aes").marshal())
        aesKeyHandle = self.ectx.create_loaded(parentHandle, inSensitive, inPublic)[0]

        ivIn = TPM2B_IV(b"thisis16byteszxc")
        inData = TPM2B_MAX_BUFFER(b"this is data to encrypt")
        outCipherText, outIV = self.ectx.encrypt_decrypt(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )
        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.encrypt_decrypt(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(bytes(inData), bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        # test plain bytes for data
        ivIn = b"thisis16byteszxc"
        inData = b"this is data to encrypt"
        outCipherText, outIV = self.ectx.encrypt_decrypt(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )
        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.encrypt_decrypt(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(inData, bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(42.5, True, TPM2_ALG.CFB, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, object(), TPM2_ALG.CFB, ivIn, outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, object(), ivIn, outCipherText)

        with self.assertRaises(ValueError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, 42, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, TPM2B_PUBLIC(), outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, None)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session3=12.3
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, "bad Bool", TPM2_ALG.CFB, ivIn, inData
            )

    def test_encrypt_decrypt2(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()
        parentHandle = self.ectx.create_primary(inSensitive, "ecc")[0]

        inPublic = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(alg="aes").marshal())
        aesKeyHandle = self.ectx.create_loaded(parentHandle, inSensitive, inPublic)[0]

        ivIn = TPM2B_IV(b"thisis16byteszxc")
        inData = TPM2B_MAX_BUFFER(b"this is data to encrypt")
        outCipherText, outIV = self.ectx.encrypt_decrypt_2(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )

        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.encrypt_decrypt_2(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(bytes(inData), bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        ivIn = b"thisis16byteszxc"
        inData = b"this is data to encrypt"
        outCipherText, outIV = self.ectx.encrypt_decrypt_2(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )

        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.encrypt_decrypt_2(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(inData, bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(42.5, True, TPM2_ALG.CFB, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, object(), TPM2_ALG.CFB, ivIn, outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, object(), ivIn, outCipherText)

        with self.assertRaises(ValueError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, 42, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, TPM2B_PUBLIC(), outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, None)

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session3=12.3
            )

        with self.assertRaises(TypeError):
            self.ectx.encrypt_decrypt_2(
                aesKeyHandle, "Not Bool", TPM2_ALG.CFB, ivIn, inData
            )

    def test_hash(self):

        # Null hierarchy default
        digest, ticket = self.ectx.hash(b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Owner hierarchy set
        digest, ticket = self.ectx.hash(b"1234", TPM2_ALG.SHA256, ESYS_TR.OWNER)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Test TPM2B_MAX_BUFFER
        inData = TPM2B_MAX_BUFFER(b"1234")
        digest, ticket = self.ectx.hash(inData, TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Test str input
        inData = TPM2B_MAX_BUFFER("1234")
        digest, ticket = self.ectx.hash(inData, TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        with self.assertRaises(TypeError):
            self.ectx.hash(object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hash(inData, "baz")

        with self.assertRaises(ValueError):
            self.ectx.hash(inData, 42)

        with self.assertRaises(TypeError):
            self.ectx.hash(inData, TPM2_ALG.SHA256, session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.hash(inData, TPM2_ALG.SHA256, session2="baz")

        with self.assertRaises(TypeError):
            self.ectx.hash(inData, TPM2_ALG.SHA256, session3=object())

    def test_hmac(self):

        attrs = (
            TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        templ = TPMT_PUBLIC.parse(alg="hmac", objectAttributes=attrs)
        inPublic = TPM2B_PUBLIC(templ)

        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        primaryHandle = self.ectx.create_primary(inSensitive, inPublic)[0]

        # Test bytes
        hmac = self.ectx.hmac(primaryHandle, b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        # Test str
        hmac = self.ectx.hmac(primaryHandle, "1234", TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        # Test Native
        inData = TPM2B_MAX_BUFFER("1234")
        hmac = self.ectx.hmac(primaryHandle, inData, TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        with self.assertRaises(TypeError):
            self.ectx.hmac(45.6, inData, TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hmac(primaryHandle, object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hmac(primaryHandle, inData, "baz")

        with self.assertRaises(ValueError):
            self.ectx.hmac(primaryHandle, inData, 42)

        with self.assertRaises(TypeError):
            self.ectx.hmac(primaryHandle, inData, TPM2_ALG.SHA256, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.hmac(primaryHandle, inData, TPM2_ALG.SHA256, session2="object")

        with self.assertRaises(TypeError):
            self.ectx.hmac(primaryHandle, inData, TPM2_ALG.SHA256, session3=45.6)

    def test_stir_random(self):

        self.ectx.stir_random(b"1234")
        self.ectx.stir_random("1234")
        self.ectx.stir_random(TPM2B_SENSITIVE_DATA("1234"))

        with self.assertRaises(TypeError):
            self.ectx.stir_random(object())

        with self.assertRaises(TypeError):
            self.ectx.stir_random("1234", session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.stir_random("1234", session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.stir_random("1234", session3=object())

    def test_hmac_sequence(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="hmac",
                objectAttributes=(
                    TPMA_OBJECT.SIGN_ENCRYPT
                    | TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                ),
            )
        )

        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        handle = self.ectx.create_primary(inSensitive, inPublic)[0]

        seqHandle = self.ectx.hmac_start(handle, None, TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hmac_start(handle, b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hmac_start(handle, "1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hmac_start(handle, TPM2B_AUTH(b"1234"), TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)

        # self.ectx.tr_set_auth(seqHandle, b"1234")

        self.ectx.sequence_update(seqHandle, "here is some data")

        self.ectx.sequence_update(seqHandle, b"more data but byte string")

        self.ectx.sequence_update(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.sequence_update(seqHandle, None)

        digest, ticket = self.ectx.sequence_complete(seqHandle, None)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)

        self.assertEqual(len(digest), 32)

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(45.6, "1234", TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(handle, dict(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(handle, "1234", object())

        with self.assertRaises(ValueError):
            self.ectx.hmac_start(handle, "1234", 42)

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(handle, "1234", TPM2_ALG.SHA256, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(handle, "1234", TPM2_ALG.SHA256, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.hmac_start(handle, "1234", TPM2_ALG.SHA256, session3=45.6)

    def test_hash_sequence(self):

        seqHandle = self.ectx.hash_sequence_start(None, TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hash_sequence_start(b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hash_sequence_start("1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.flush_context(seqHandle)

        seqHandle = self.ectx.hash_sequence_start(TPM2B_AUTH(b"1234"), TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)

        self.ectx.tr_set_auth(seqHandle, b"1234")

        self.ectx.sequence_update(seqHandle, "here is some data")

        self.ectx.sequence_update(seqHandle, b"more data but byte string")

        self.ectx.sequence_update(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.sequence_update(seqHandle, None)

        digest, ticket = self.ectx.sequence_complete(seqHandle, "AnotherBuffer")
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)

        e = binascii.unhexlify(
            "a02271d78e351c6e9e775b0570b440d3ac37ad6c02a3b69df940f3f893f80d41"
        )
        d = bytes(digest)
        self.assertEqual(e, d)

        with self.assertRaises(TypeError):
            self.ectx.hash_sequence_start(object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.hash_sequence_start(b"1234", "dssdf")

        with self.assertRaises(ValueError):
            self.ectx.hash_sequence_start(b"1234", 42)

        with self.assertRaises(TypeError):
            self.ectx.hash_sequence_start(b"1234", TPM2_ALG.SHA256, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.hash_sequence_start(b"1234", TPM2_ALG.SHA256, session2=56.7)

        with self.assertRaises(TypeError):
            self.ectx.hash_sequence_start(
                b"1234", TPM2_ALG.SHA256, session3=TPM2B_DATA()
            )

        with self.assertRaises(TypeError):
            self.ectx.sequence_update(56.7, "here is some data")

        with self.assertRaises(TypeError):
            self.ectx.sequence_update(seqHandle, [])

        with self.assertRaises(TypeError):
            self.ectx.sequence_update(seqHandle, "here is some data", sequence1="foo")

        with self.assertRaises(TypeError):
            self.ectx.sequence_update(
                seqHandle, "here is some data", sequence2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.sequence_update(seqHandle, "here is some data", sequence3=78.23)

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(78.25, "AnotherBuffer")

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(seqHandle, [])

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(seqHandle, "AnotherBuffer", hierarchy=object())

        with self.assertRaises(ValueError):
            self.ectx.sequence_complete(seqHandle, "AnotherBuffer", hierarchy=42)

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(seqHandle, "AnotherBuffer", session1=42.67)

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(seqHandle, "AnotherBuffer", session2="baz")

        with self.assertRaises(TypeError):
            self.ectx.sequence_complete(seqHandle, "AnotherBuffer", session3=object())

    def test_event_sequence_complete(self):

        seqHandle = self.ectx.hash_sequence_start(TPM2B_AUTH(b"1234"), TPM2_ALG.NULL)
        self.assertNotEqual(seqHandle, 0)

        self.ectx.tr_set_auth(seqHandle, b"1234")

        self.ectx.sequence_update(seqHandle, "here is some data")

        self.ectx.sequence_update(seqHandle, b"more data but byte string")

        self.ectx.sequence_update(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.sequence_update(seqHandle, None)

        pcrs = self.ectx.event_sequence_complete(
            ESYS_TR.PCR16, seqHandle, "AnotherBuffer"
        )
        self.assertEqual(type(pcrs), TPML_DIGEST_VALUES)

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(object(), seqHandle, None)

        with self.assertRaises(ValueError):
            self.ectx.event_sequence_complete(42, seqHandle, None)

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(ESYS_TR.PCR16, 46.5, None)

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(ESYS_TR.PCR16, seqHandle, object())

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(
                ESYS_TR.PCR16, seqHandle, None, sequence1=67.34
            )

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(
                ESYS_TR.PCR16, seqHandle, None, sequence2="boo"
            )

        with self.assertRaises(TypeError):
            self.ectx.event_sequence_complete(
                ESYS_TR.PCR16, seqHandle, None, sequence3=object()
            )

    def test_context_save_context_load(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        handle, outpub, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        ctx = self.ectx.context_save(handle)

        nhandle = self.ectx.context_load(ctx)
        name = self.ectx.tr_get_name(nhandle)

        self.assertEqual(bytes(outpub.get_name()), bytes(name))

    def test_flush_context(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        self.ectx.flush_context(handle)
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.tr_get_name(handle)
        self.assertEqual(e.exception.error, TSS2_RC.ESYS_RC_BAD_TR)

    def test_evict_control(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        handle, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        self.ectx.evict_control(
            ESYS_TR.OWNER, handle, 0x81000081, session1=ESYS_TR.PASSWORD
        )
        phandle = self.ectx.tr_from_tpmpublic(0x81000081)
        self.ectx.evict_control(
            ESYS_TR.OWNER, phandle, 0x81000081, session1=ESYS_TR.PASSWORD
        )
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.tr_from_tpmpublic(0x81000081)
        self.assertEqual(e.exception.error, TPM2_RC.HANDLE)

    def test_get_capability(self):
        more = True
        while more:
            more, capdata = self.ectx.get_capability(
                TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC
            )
            for c in capdata.data.command:
                pass

        with self.assertRaises(TypeError):
            self.ectx.get_capability("Not valid", TPM2_CC.FIRST, TPM2_MAX.CAP_CC)

        with self.assertRaises(TypeError):
            self.ectx.get_capability(TPM2_CAP.COMMANDS, 45.6, TPM2_MAX.CAP_CC)

        with self.assertRaises(TypeError):
            self.ectx.get_capability(TPM2_CAP.COMMANDS, TPM2_CC.FIRST, [])

        with self.assertRaises(TypeError):
            self.ectx.get_capability(
                TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC, session1=56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.get_capability(
                TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.get_capability(
                TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC, session3="baz"
            )

    def test_test_parms(self):
        parms = TPMT_PUBLIC_PARMS(type=TPM2_ALG.RSA)
        parms.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG.NULL
        parms.parameters.rsaDetail.scheme.scheme = TPM2_ALG.NULL
        parms.parameters.rsaDetail.keyBits = 2048
        parms.parameters.rsaDetail.exponent = 0

        self.ectx.test_parms(parms)

        parms.parameters.rsaDetail.keyBits = 1234
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.test_parms(parms)
        self.assertEqual(e.exception.error, TPM2_RC.VALUE)
        self.assertEqual(e.exception.parameter, 1)

    def test_read_clock(self):
        ctime = self.ectx.read_clock()
        self.assertGreater(ctime.time, 0)
        self.assertGreater(ctime.clockInfo.clock, 0)

    def test_clock_set(self):
        newtime = 0xFA1AFE1
        self.ectx.clock_set(newtime)
        ntime = self.ectx.read_clock()
        self.assertGreaterEqual(ntime.clockInfo.clock, newtime)

        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.clock_set(0)
        self.assertEqual(e.exception.error, TPM2_RC.VALUE)

    def test_clock_rate_adjust(self):
        self.ectx.clock_rate_adjust(TPM2_CLOCK.COARSE_SLOWER)

    def test_nv_undefine_space_special(self):
        # pre-generated TPM2_PolicyCommandCode(TPM2_CC_NV_UndefineSpaceSpecial)
        pol = b"\x1d-\xc4\x85\xe1w\xdd\xd0\xa4\n4I\x13\xce\xebB\x0c\xaa\t<BX}.\x1b\x13+\x15|\xcb]\xb0"
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.PPWRITE
                | TPMA_NV.PPREAD
                | TPMA_NV.PLATFORMCREATE
                | TPMA_NV.POLICY_DELETE,
                authPolicy=pol,
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(
            b"", nvpub, auth_handle=ESYS_TR.RH_PLATFORM
        )

        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        self.ectx.policy_command_code(session, TPM2_CC.NV_UndefineSpaceSpecial)

        self.ectx.nv_undefine_space_special(nvhandle, session1=session)

    def test_nv_read_public(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        pubout, name = self.ectx.nv_read_public(nvhandle)

        self.assertEqual(nvpub.get_name().name, name.name)

    def test_nv_increment(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE
                | (TPM2_NT.COUNTER << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        self.ectx.nv_increment(nvhandle, auth_handle=ESYS_TR.RH_OWNER)

        self.ectx.nv_increment(nvhandle)

        data = self.ectx.nv_read(nvhandle, 8, 0, auth_handle=ESYS_TR.RH_OWNER)

        counter = int.from_bytes(data.buffer, byteorder="big")
        self.assertEqual(counter, 2)

        with self.assertRaises(TypeError):
            self.ectx.nv_increment("foo")

        with self.assertRaises(TypeError):
            self.ectx.nv_increment(nvhandle, auth_handle="bar")

        with self.assertRaises(TypeError):
            self.ectx.nv_increment(nvhandle, session1=45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_increment(nvhandle, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.nv_increment(nvhandle, session3="baz")

    def test_nv_extend(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE
                | (TPM2_NT.EXTEND << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=32,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        edata = b"\xFF" * 32
        self.ectx.nv_extend(nvhandle, edata, auth_handle=ESYS_TR.RH_OWNER)
        self.ectx.nv_extend(nvhandle, edata)

        data = self.ectx.nv_read(nvhandle, 32, 0, auth_handle=ESYS_TR.RH_OWNER)

        edigest = b"\x10l\xc9ey]W\x01\xde\x94\x048\xf5\x08\x0fS'h\xbc\x98\xb5\x9bg\xf9g\xa4(\x1d\xc2\x83Z\xef"
        self.assertEqual(edigest, bytes(data))

        with self.assertRaises(TypeError):
            self.ectx.nv_extend("handle", edata)

        with self.assertRaises(TypeError):
            self.ectx.nv_extend(nvhandle, TPM2B_CONTEXT_DATA())

        with self.assertRaises(TypeError):
            self.ectx.nv_extend(nvhandle, edata, auth_handle=34.7)

        with self.assertRaises(TypeError):
            self.ectx.nv_extend(nvhandle, edata, session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.nv_extend(nvhandle, edata, session2=56.9)

        with self.assertRaises(TypeError):
            self.ectx.nv_extend(nvhandle, edata, session3=object)

    def test_nv_set_bits(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE
                | (TPM2_NT.BITS << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        bits = 0b1010
        self.ectx.nv_set_bits(nvhandle, bits, auth_handle=ESYS_TR.RH_OWNER)
        bits = 0b1011
        self.ectx.nv_set_bits(nvhandle, bits)

        data = self.ectx.nv_read(nvhandle, 8, 0, auth_handle=ESYS_TR.RH_OWNER)

        b = bits.to_bytes(length=8, byteorder="big")
        self.assertEqual(b, bytes(data))

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits("not a handle", bits)

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits(nvhandle, object())

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits(nvhandle, bits, auth_handle=45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits(nvhandle, bits, session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits(nvhandle, bits, session2=45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_set_bits(nvhandle, bits, session3=object())

    def test_nv_write_lock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.WRITE_STCLEAR
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        self.ectx.nv_write_lock(nvhandle, auth_handle=ESYS_TR.RH_OWNER)
        self.ectx.nv_write_lock(nvhandle)

        indata = b"12345678"
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.nv_write(nvhandle, indata, auth_handle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

        with self.assertRaises(TypeError):
            self.ectx.nv_write_lock(list())

        with self.assertRaises(TypeError):
            self.ectx.nv_write_lock(nvhandle, auth_handle=42.3)

        with self.assertRaises(TypeError):
            self.ectx.nv_write_lock(nvhandle, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.nv_write_lock(nvhandle, session2=45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_write_lock(nvhandle, session3=list())

    def test_nv_global_write_lock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD | TPMA_NV.GLOBALLOCK,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        self.ectx.nv_global_write_lock()

        indata = b"12345678"
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.nv_write(nvhandle, indata, auth_handle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

    def test_nv_read_lock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE
                | TPMA_NV.READ_STCLEAR,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        indata = b"12345678"
        self.ectx.nv_write(nvhandle, indata, auth_handle=ESYS_TR.RH_OWNER)

        self.ectx.nv_read_lock(nvhandle, auth_handle=ESYS_TR.RH_OWNER)
        self.ectx.nv_read_lock(nvhandle)
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.nv_read(nvhandle, 8, auth_handle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

        with self.assertRaises(TypeError):
            self.ectx.nv_read_lock("handle")

        with self.assertRaises(TypeError):
            self.ectx.nv_read_lock(nvhandle, auth_handle=45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_read_lock(nvhandle, session1=56.9)

        with self.assertRaises(TypeError):
            self.ectx.nv_read_lock(nvhandle, sesiosn2=object())

        with self.assertRaises(TypeError):
            self.ectx.nv_read_lock(nvhandle, session3="baz")

    def test_nv_change_auth(self):
        # pre-generated TPM2_PolicyCommandCode(TPM2_CC_NV_ChangeAuth)
        pol = b"D^\xd9S`\x1a\x04U\x04U\t\x99\xbf,\xbb)\x92\xcb\xa2\xdb\xb5\x12\x1b\xcf\x03\x86\x9fe\xb5\x0c&\xe5"
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD | TPMA_NV.AUTHREAD,
                authPolicy=pol,
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"first", nvpub)
        self.ectx.nv_write(nvhandle, b"sometest", auth_handle=ESYS_TR.RH_OWNER)

        self.ectx.nv_read(nvhandle, 8, auth_handle=nvhandle)

        session = self.ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        self.ectx.policy_command_code(session, TPM2_CC.NV_ChangeAuth)

        self.ectx.nv_change_auth(nvhandle, b"second", session1=session)

        self.ectx.nv_read(nvhandle, 8, auth_handle=nvhandle)

    def test_nv_certify(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.AUTHREAD
                | TPMA_NV.AUTHWRITE,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)
        self.ectx.nv_write(nvhandle, b"sometest", auth_handle=ESYS_TR.RH_OWNER)

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        eccHandle, signPub, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        qualifyingData = TPM2B_DATA(b"qdata")
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)

        certifyInfo, _ = self.ectx.nv_certify(
            eccHandle,
            nvhandle,
            qualifyingData,
            inScheme,
            8,
            auth_handle=ESYS_TR.RH_OWNER,
            session1=ESYS_TR.PASSWORD,
            session2=ESYS_TR.PASSWORD,
        )
        att, _ = TPMS_ATTEST.unmarshal(bytes(certifyInfo))
        self.assertEqual(att.magic, TPM2_GENERATED_VALUE(0xFF544347))
        self.assertEqual(att.type, TPM2_ST.ATTEST_NV)
        self.assertEqual(bytes(att.extraData), b"qdata")
        nvpub.nvPublic.attributes = nvpub.nvPublic.attributes | TPMA_NV.WRITTEN
        self.assertEqual(bytes(att.attested.nv.indexName), bytes(nvpub.get_name()))
        self.assertEqual(att.attested.nv.offset, 0)
        self.assertEqual(att.attested.nv.nvContents.buffer, b"sometest")

        self.ectx.nv_certify(eccHandle, nvhandle, qualifyingData, inScheme, 8)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(67.7, nvhandle, qualifyingData, inScheme, 8)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(eccHandle, "bad handle", qualifyingData, inScheme, 8)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(eccHandle, nvhandle, object(), inScheme, 8)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(eccHandle, nvhandle, qualifyingData, TPM2B_DATA(), 8)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(eccHandle, nvhandle, qualifyingData, inScheme, 45.6)

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(
                eccHandle, nvhandle, qualifyingData, inScheme, 8, offset="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(
                eccHandle, nvhandle, qualifyingData, inScheme, 8, auth_handle=object
            )

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(
                eccHandle, nvhandle, qualifyingData, inScheme, 8, session1=67.8
            )

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(
                eccHandle, nvhandle, qualifyingData, inScheme, 8, session2="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.nv_certify(
                eccHandle, nvhandle, qualifyingData, inScheme, 8, session3=[]
            )

    def test_certify(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        eccHandle = self.ectx.create_primary(inSensitive, inPublic)[0]

        qualifyingData = TPM2B_DATA()
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        certifyInfo, signature = self.ectx.certify(
            eccHandle, eccHandle, qualifyingData, inScheme
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        certifyInfo, signature = self.ectx.certify(
            eccHandle, eccHandle, b"12345678", inScheme
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.certify(
                TPM2B_ATTEST(), eccHandle, qualifyingData, inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.certify(
                eccHandle, 2.0, qualifyingData, inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.certify(
                eccHandle, eccHandle, TPM2B_PUBLIC(), inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.certify(
                eccHandle, eccHandle, qualifyingData, TPM2B_PRIVATE()
            )

        with self.assertRaises(TypeError):
            self.ectx.certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session1=56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session3=object()
            )

    def test_certify_creation(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        eccHandle, _, _, creationHash, creationTicket = self.ectx.create_primary(
            inSensitive, inPublic
        )

        qualifyingData = TPM2B_DATA()
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        certifyInfo, signature = self.ectx.certify_creation(
            eccHandle, eccHandle, qualifyingData, creationHash, inScheme, creationTicket
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                45.6, eccHandle, qualifyingData, creationHash, inScheme, creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle,
                object(),
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle,
                eccHandle,
                TPM2B_PUBLIC(),
                creationHash,
                inScheme,
                creationTicket,
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle, eccHandle, qualifyingData, object(), inScheme, creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle, eccHandle, qualifyingData, creationHash, [], creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle, eccHandle, qualifyingData, creationHash, inScheme, 56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session1=56.7,
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session2=object(),
            )

        with self.assertRaises(TypeError):
            self.ectx.certify_creation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session3="baz",
            )

    def test_vendor_tcg_test(self):

        # Maybe some TPMs support the CC some don't
        capdata = self.ectx.get_capability(
            TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC
        )[1]

        # TPM Supports it
        if TPM2_CC.Vendor_TCG_Test in capdata.data.command:
            self.ectx.vendor_tcg_test(b"random data")

            in_cdata = TPM2B_DATA(b"other bytes")._cdata
            self.ectx.vendor_tcg_test(in_cdata)
        # TPM Does not Support it
        else:
            with self.assertRaises(TSS2_Exception):
                self.ectx.vendor_tcg_test(b"random data")

            in_cdata = TPM2B_DATA(b"other bytes")._cdata
            with self.assertRaises(TSS2_Exception):
                self.ectx.vendor_tcg_test(in_cdata)

        with self.assertRaises(TypeError):
            self.ectx.vendor_tcg_test(None)

        with self.assertRaises(TypeError):
            self.ectx.vendor_tcg_test(TPM2B_PUBLIC())

    def test_field_upgrade_start(self):
        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa:rsassa-sha256",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE()

        keyhandle, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.field_upgrade_start(
                keyhandle, b"", TPMT_SIGNATURE(sigAlg=TPM2_ALG.NULL),
            )
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_field_upgrade_data(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.field_upgrade_data(b"")
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_firmware_read(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.firmware_read(0)
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_shutdown_no_arg(self):
        self.ectx.shutdown(TPM2_SU.STATE)

    def test_shutdown_state(self):
        self.ectx.shutdown(TPM2_SU.STATE)

    def test_shutdown_clear(self):
        self.ectx.shutdown(TPM2_SU.CLEAR)

    def test_shutdown_bad(self):
        with self.assertRaises(TypeError):
            self.ectx.shutdown(object())

        with self.assertRaises(ValueError):
            self.ectx.shutdown(42)

        with self.assertRaises(TypeError):
            self.ectx.shutdown(session1=object())

        with self.assertRaises(TypeError):
            self.ectx.shutdown(session2=object())

        with self.assertRaises(TypeError):
            self.ectx.shutdown(session3=object())

    def test_policyrestart(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_restart(session)

        with self.assertRaises(TypeError):
            self.ectx.policy_restart(object())

        with self.assertRaises(TypeError):
            self.ectx.policy_restart(session, session1=4.5)

        with self.assertRaises(TypeError):
            self.ectx.policy_restart(session, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.policy_restart(session, session3=33.666)

    def test_duplicate(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.policy_get_digest(session)
        self.ectx.flush_context(session)
        session = None

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )

        inSensitive = TPM2B_SENSITIVE_CREATE()

        primary1, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic,)

        primary2, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:aes128cfb",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inPublic.publicArea.authPolicy = policyDigest

        priv, pub, _, _, _ = self.ectx.create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.load(primary1, priv, pub)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)

        encryptionKey = TPM2B_DATA("is sixteen bytes")

        sym = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        encryptionKeyOut, duplicate, symSeed = self.ectx.duplicate(
            childHandle, primary2, encryptionKey, sym, session1=session
        )
        self.assertEqual(type(encryptionKeyOut), TPM2B_DATA)
        self.assertEqual(type(duplicate), TPM2B_PRIVATE)
        self.assertEqual(type(symSeed), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.duplicate(6.7, primary2, encryptionKey, sym, session1=session)

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle, object(), encryptionKey, sym, session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle, primary2, TPM2B_PUBLIC(), sym, session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle, primary2, encryptionKey, b"1234", session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle, primary2, encryptionKey, sym, session1=7.89
            )

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle,
                primary2,
                encryptionKey,
                sym,
                session1=session,
                session2="foo",
            )

        with self.assertRaises(TypeError):
            self.ectx.duplicate(
                childHandle,
                primary2,
                encryptionKey,
                sym,
                session1=session,
                session2=ESYS_TR.PASSWORD,
                session3="foo",
            )

    def test_policy_auth_value(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)

        with self.assertRaises(TypeError):
            self.ectx.policy_auth_value(b"1234")

    def test_policy_command_code(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)

        with self.assertRaises(TypeError):
            self.ectx.policy_command_code(b"1234", TPM2_CC.Duplicate)

        with self.assertRaises(TypeError):
            self.ectx.policy_command_code(session, b"12345")

        with self.assertRaises(ValueError):
            self.ectx.policy_command_code(session, 42)

    def test_policy_get_digest(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.policy_get_digest(session)
        self.assertTrue(type(policyDigest), TPM2B_DIGEST)

    def test_rewrap(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.policy_get_digest(session)
        self.ectx.flush_context(session)
        session = None

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )

        inSensitive = TPM2B_SENSITIVE_CREATE()

        primary1, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        primary2, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:aes128cfb",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inPublic.publicArea.authPolicy = policyDigest

        priv, pub, _, _, _ = self.ectx.create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.load(primary1, priv, pub)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)

        encryptionKey = TPM2B_DATA("is sixteen bytes")

        sym = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        _, duplicate, symSeed = self.ectx.duplicate(
            childHandle, primary2, encryptionKey, sym, session1=session
        )

        keyName = pub.publicArea.get_name()
        duplicate, symSeed = self.ectx.rewrap(
            primary2, primary1, duplicate, keyName, symSeed
        )
        self.assertEqual(type(duplicate), TPM2B_PRIVATE)
        self.assertEqual(type(symSeed), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.rewrap(67.3, primary1, duplicate, keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.rewrap(primary2, object(), duplicate, keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.rewrap(primary2, primary1, TPM2B_NAME(), keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.rewrap(primary2, primary1, duplicate, TPM2B_PRIVATE(), symSeed)

        with self.assertRaises(TypeError):
            self.ectx.rewrap(
                primary2, primary1, duplicate, keyName, symSeed, session1="goo"
            )

        with self.assertRaises(TypeError):
            self.ectx.rewrap(
                primary2, primary1, duplicate, keyName, symSeed, session2=45.6
            )

        with self.assertRaises(TypeError):
            self.ectx.rewrap(
                primary2, primary1, duplicate, keyName, symSeed, sesion3=object()
            )

    def test_import(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.policy_get_digest(session)
        self.ectx.flush_context(session)
        session = None

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )

        inSensitive = TPM2B_SENSITIVE_CREATE()

        primary1, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        primary2, _, _, _, _ = self.ectx.create_primary(inSensitive, inPublic)

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:aes128cfb",
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )
        inPublic.publicArea.authPolicy = policyDigest

        priv, pub, _, _, _ = self.ectx.create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.load(primary1, priv, pub)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_auth_value(session)
        self.ectx.policy_command_code(session, TPM2_CC.Duplicate)

        sym = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL,)

        encryptionKey, duplicate, symSeed = self.ectx.duplicate(
            childHandle, primary2, None, sym, session1=session
        )

        private = self.ectx.import_(
            primary1, encryptionKey, pub, duplicate, symSeed, sym
        )

        self.assertEqual(type(private), TPM2B_PRIVATE)

        with self.assertRaises(TypeError):
            self.ectx.import_(98.5, encryptionKey, pub, duplicate, symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.import_(primary1, TPM2B_ECC_POINT(), pub, duplicate, symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.import_(
                primary1, encryptionKey, TPM2B_DATA(), duplicate, symSeed, sym
            )

        with self.assertRaises(TypeError):
            self.ectx.import_(primary1, encryptionKey, pub, object(), symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.import_(primary1, encryptionKey, pub, duplicate, None, sym)

        with self.assertRaises(TypeError):
            self.ectx.import_(
                primary1, encryptionKey, pub, duplicate, symSeed, TPM2B_PUBLIC()
            )

        with self.assertRaises(TypeError):
            self.ectx.import_(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session1="boo"
            )

        with self.assertRaises(TypeError):
            self.ectx.import_(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.import_(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session3=4.5
            )

    def test_quote(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="ecc:ecdsa",
                objectAttributes=TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            )
        )

        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        parentHandle = self.ectx.create_primary(inSensitive, inPublic)[0]

        quote, signature = self.ectx.quote(
            parentHandle, "sha256:1,2,3,4", TPM2B_DATA(b"123456789")
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        quote, signature = self.ectx.quote(
            parentHandle, TPML_PCR_SELECTION.parse("sha256:1,2,3,4"), TPM2B_DATA()
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        quote, signature = self.ectx.quote(
            parentHandle,
            "sha256:1,2,3,4",
            TPM2B_DATA(),
            in_scheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.quote(42.0, "sha256:1,2,3,4", TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, b"sha256:1,2,3,4")

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, "sha256:1,2,3,4", qualifying_data=object())

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, "sha256:1,2,3,4", in_scheme=87)

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, "sha256:1,2,3,4", session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, "sha256:1,2,3,4", session2=25.68)

        with self.assertRaises(TypeError):
            self.ectx.quote(parentHandle, "sha256:1,2,3,4", session3=object())

    def test_get_session_audit_digest(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:rsassa:null",
                objectAttributes=TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
                | TPMA_OBJECT.RESTRICTED,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        signHandle = self.ectx.create_primary(inSensitive, inPublic)[0]

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL,)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.HMAC,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.trsess_set_attributes(
            session, TPMA_SESSION.AUDIT | TPMA_SESSION.CONTINUESESSION
        )

        self.ectx.get_capability(
            TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC, session1=session
        )

        auditInfo, signature = self.ectx.get_session_audit_digest(
            signHandle, session, b"1234"
        )
        self.assertEqual(type(auditInfo), TPM2B_ATTEST)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(45.89, session, b"1234")

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(signHandle, object(), b"1234")

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(signHandle, session, list())

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(
                signHandle, session, b"1234", privacy_admin_handle=45.6
            )

        with self.assertRaises(ValueError):
            self.ectx.get_session_audit_digest(
                signHandle, session, b"1234", privacy_admin_handle=ESYS_TR.LOCKOUT
            )

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(
                signHandle, session, b"1234", session1="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(
                signHandle, session, b"1234", session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.get_session_audit_digest(
                signHandle, session, b"1234", session3=12.723
            )

    def test_pp_commands(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.pp_commands(TPML_CC(), TPML_CC(), session1=ESYS_TR.PASSWORD)
        self.assertEqual(e.exception.error, TPM2_RC.PP)
        self.assertEqual(e.exception.session, 1)

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(b"bad setList", TPML_CC(), session1=ESYS_TR.PASSWORD)

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(TPML_CC(), None, session1=ESYS_TR.PASSWORD)

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(TPML_CC(), TPML_CC(), session1=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(TPML_CC(), TPML_CC(), session2=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(TPML_CC(), TPML_CC(), session3=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.pp_commands(TPML_CC(), TPML_CC(), authHandle="platform")

    def test_set_algorithm_set(self):
        self.ectx.set_algorithm_set(0)

        with self.assertRaises(TypeError):
            self.ectx.set_algorithm_set([1, 2, 3])

        with self.assertRaises(TypeError):
            self.ectx.set_algorithm_set(session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.set_algorithm_set(session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.set_algorithm_set(session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.set_algorithm_set(auth_handle=None)

    def test_dictionary_attack_lock_reset(self):
        self.ectx.dictionary_attack_lock_reset()

        with self.assertRaises(ValueError):
            self.ectx.dictionary_attack_lock_reset(lock_handle=ESYS_TR.RH_OWNER)

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_lock_reset([1, 2, 3])

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_lock_reset(session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_lock_reset(session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_lock_reset(session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_lock_reset(lock_handle=None)

    def test_dictionary_attack_parameters(self):
        self.ectx.dictionary_attack_parameters(1, 2, 3)

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(None, 2, 3)

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, None, 3)

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, 2, None)

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, 2, 3, session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, 2, 3, session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, 2, 3, session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.dictionary_attack_parameters(1, 2, 3, lock_handle=None)

    def test_get_command_audit_digest(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="rsa2048:rsassa:null",
                objectAttributes=TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
                | TPMA_OBJECT.RESTRICTED,
            )
        )

        signHandle = self.ectx.create_primary(TPM2B_SENSITIVE_CREATE(), inPublic)[0]

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.HMAC,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.trsess_set_attributes(
            session, TPMA_SESSION.AUDIT | TPMA_SESSION.CONTINUESESSION
        )

        self.ectx.get_capability(
            TPM2_CAP.COMMANDS, TPM2_CC.FIRST, TPM2_MAX.CAP_CC, session1=session
        )

        auditInfo, signature = self.ectx.get_command_audit_digest(
            signHandle, b"12345678"
        )
        self.assertEqual(type(auditInfo), TPM2B_ATTEST)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(45.89, b"1234")

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(signHandle, b"1234", list())

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(signHandle, b"1234", privacy_handle=45.6)

        with self.assertRaises(ValueError):
            self.ectx.get_command_audit_digest(
                signHandle, b"1234", privacy_handle=ESYS_TR.LOCKOUT
            )

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(signHandle, b"1234", session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(signHandle, b"1234", session2=object())

        with self.assertRaises(TypeError):
            self.ectx.get_command_audit_digest(signHandle, b"1234", session3=12.723)

    def test_get_time(self):

        inPublic = TPM2B_PUBLIC.parse(
            alg="rsa2048:rsassa:null",
            objectAttributes=TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
            | TPMA_OBJECT.RESTRICTED,
        )
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        signHandle = self.ectx.create_primary(inSensitive, inPublic)[0]

        auditInfo, signature = self.ectx.get_time(signHandle, b"12345678")
        self.assertTrue(type(auditInfo), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
        scheme.details.rsassa.hashAlg = TPM2_ALG.SHA256

        auditInfo, signature = self.ectx.get_time(
            signHandle, b"12345678", in_scheme=scheme
        )
        self.assertTrue(type(auditInfo), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.get_time(45.89, b"1234")

        with self.assertRaises(TypeError):
            self.ectx.get_time(signHandle, list())

        with self.assertRaises(TypeError):
            self.ectx.get_time(signHandle, b"1234", privacy_admin_handle=45.6)

        with self.assertRaises(ValueError):
            self.ectx.get_time(
                signHandle, b"1234", privacy_admin_handle=ESYS_TR.LOCKOUT
            )

        with self.assertRaises(TypeError):
            self.ectx.get_time(signHandle, b"1234", session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.get_time(signHandle, b"1234", session2=object())

        with self.assertRaises(TypeError):
            self.ectx.get_time(signHandle, b"1234", session3=12.723)

    def test_commit(self):

        p = TPM2B_PUBLIC.parse(
            "ecc:ecdaa",
            (
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
            ),
        )

        signHandle = self.ectx.create_primary(TPM2B_SENSITIVE_CREATE(), p)[0]

        P1 = TPM2B_ECC_POINT()
        s2 = TPM2B_SENSITIVE_DATA()
        y2 = TPM2B_ECC_PARAMETER()
        K, L, E, counter = self.ectx.commit(signHandle, P1, s2, y2)
        self.assertEqual(type(K), TPM2B_ECC_POINT)
        self.assertEqual(type(L), TPM2B_ECC_POINT)
        self.assertEqual(type(E), TPM2B_ECC_POINT)
        self.assertEqual(0, counter)

        with self.assertRaises(TypeError):
            self.ectx.commit("nope", P1, s2, y2)

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, list(), s2, y2)

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, P1, TPM2B_SENSITIVE_DATA, y2)

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, P1, s2, 16)

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, P1, s2, y2, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, P1, s2, y2, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.commit(signHandle, P1, s2, y2, session3=67.5)

    def test_sign(self):

        sign_handle = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa",
                (
                    TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.SIGN_ENCRYPT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                ),
            ),
        )[0]
        digest = b"0123456789abcdef0987654321fedcba"
        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSAPSS)
        scheme.details.any.hashAlg = TPM2_ALG.SHA256
        validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
        signature = self.ectx.sign(sign_handle, digest, scheme, validation)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        signature = self.ectx.sign(
            sign_handle, TPM2B_DIGEST(digest), scheme, validation
        )
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.sign("not valid", digest, scheme, validation)

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, object, scheme, validation)

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, digest, "not a scheme", validation)

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, digest, scheme, list())

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, digest, scheme, validation, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, digest, scheme, validation, session2=56.5)

        with self.assertRaises(TypeError):
            self.ectx.sign(sign_handle, digest, scheme, validation, session3=object())

    def test_verify_signature(self):

        sign_handle = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa",
                (
                    TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.SIGN_ENCRYPT
                    | TPMA_OBJECT.FIXEDTPM
                    | TPMA_OBJECT.FIXEDPARENT
                    | TPMA_OBJECT.SENSITIVEDATAORIGIN
                ),
            ),
        )[0]
        digest = b"0123456789abcdef0987654321fedcba"
        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSAPSS)
        scheme.details.any.hashAlg = TPM2_ALG.SHA256
        validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
        signature = self.ectx.sign(sign_handle, digest, scheme, validation)

        verified = self.ectx.verify_signature(sign_handle, digest, signature)
        self.assertEqual(type(verified), TPMT_TK_VERIFIED)

        verified = self.ectx.verify_signature(
            sign_handle, TPM2B_DIGEST(digest), signature
        )
        self.assertEqual(type(verified), TPMT_TK_VERIFIED)

        with self.assertRaises(TypeError):
            self.ectx.verify_signature("nope", digest, signature)

        with self.assertRaises(TypeError):
            self.ectx.verify_signature(sign_handle, object(), signature)

        with self.assertRaises(TypeError):
            self.ectx.verify_signature(sign_handle, digest, 12.56)

        with self.assertRaises(TypeError):
            self.ectx.verify_signature(sign_handle, digest, signature, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.verify_signature(sign_handle, digest, signature, session2=12.3)

        with self.assertRaises(TypeError):
            self.ectx.verify_signature(sign_handle, digest, signature, session3={})

    def test_set_command_code_audit_status(self):

        self.ectx.set_command_code_audit_status(TPM2_ALG.SHA256, TPML_CC(), TPML_CC())

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(42.6, TPML_CC(), TPML_CC())

        with self.assertRaises(ValueError):
            self.ectx.set_command_code_audit_status(42, TPML_CC(), TPML_CC())

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_ALG(), TPML_CC()
            )

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), object()
            )

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), TPML_CC(), auth=45.6
            )

        with self.assertRaises(ValueError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), TPML_CC(), auth=ESYS_TR.ENDORSEMENT
            )

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), TPML_CC(), session1=45.6
            )

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), TPML_CC(), session2="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.set_command_code_audit_status(
                TPM2_ALG.SHA256, TPML_CC(), TPML_CC(), session3=[]
            )

    def test_pcr_extend(self):

        digests = TPML_DIGEST_VALUES(
            [
                TPMT_HA(
                    hashAlg=TPM2_ALG.SHA1, digest=TPMU_HA(sha1=b"0123456789abcdeffedc")
                ),
                TPMT_HA(
                    hashAlg=TPM2_ALG.SHA256,
                    digest=TPMU_HA(sha256=b"0123456789abcdeffedcba9876543210"),
                ),
            ]
        )

        self.ectx.pcr_extend(ESYS_TR.PCR16, digests)

    def test_pcr_event(self):

        digests = self.ectx.pcr_event(ESYS_TR.PCR0, b"01234567890123456789")
        self.assertEqual(type(digests), TPML_DIGEST_VALUES)

        digests = self.ectx.pcr_event(
            ESYS_TR.PCR0, TPM2B_EVENT(b"01234567890123456789")
        )
        self.assertEqual(type(digests), TPML_DIGEST_VALUES)

        with self.assertRaises(TypeError):
            self.ectx.pcr_event("foo", b"01234567890123456789")

        with self.assertRaises(TypeError):
            self.ectx.pcr_event(ESYS_TR.PCR0, object)

        with self.assertRaises(TypeError):
            self.ectx.pcr_event(ESYS_TR.PCR0, b"01234567890123456789", session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.pcr_event(
                ESYS_TR.PCR0, b"01234567890123456789", session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.pcr_event(
                ESYS_TR.PCR0, b"01234567890123456789", session3=TPML_ALG()
            )

    def test_pcr_allocate(self):

        pcrsels = TPML_PCR_SELECTION.parse("sha1:3+sha256:all")

        success, max_, needed, available = self.ectx.pcr_allocate(pcrsels)
        self.assertEqual(type(success), bool)
        self.assertEqual(type(max_), int)
        self.assertEqual(type(needed), int)
        self.assertEqual(type(available), int)

        with self.assertRaises(TypeError):
            self.ectx.pcr_allocate(object)

        with self.assertRaises(TypeError):
            self.ectx.pcr_allocate(auth_handle="foo")

        with self.assertRaises(ValueError):
            self.ectx.pcr_allocate(pcrsels, auth_handle=ESYS_TR.OWNER)

        with self.assertRaises(TypeError):
            self.ectx.pcr_allocate(pcrsels, session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.pcr_allocate(pcrsels, session2=12.3)

        with self.assertRaises(TypeError):
            self.ectx.pcr_allocate(pcrsels, session3=object())

    def test_pcr_set_auth_policy(self):

        policy = b"0123456789ABCDEF0123456789ABCDEF"
        self.ectx.pcr_set_auth_policy(policy, TPM2_ALG.SHA256, ESYS_TR.PCR20)

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(object, TPM2_ALG.SHA256, ESYS_TR.PCR20)

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(policy, "bar", ESYS_TR.PCR20)

        with self.assertRaises(ValueError):
            self.ectx.pcr_set_auth_policy(policy, 42, ESYS_TR.PCR20)

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(policy, TPM2_ALG.SHA256, "baz")

        with self.assertRaises(ValueError):
            self.ectx.pcr_set_auth_policy(policy, TPM2_ALG.SHA256, 42)

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(
                policy, TPM2_ALG.SHA256, ESYS_TR.PCR20, auth_handle="foo"
            )

        with self.assertRaises(ValueError):
            self.ectx.pcr_set_auth_policy(
                policy, TPM2_ALG.SHA256, ESYS_TR.PCR20, auth_handle=ESYS_TR.OWNER
            )

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(
                policy, TPM2_ALG.SHA256, ESYS_TR.PCR20, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(
                policy, TPM2_ALG.SHA256, ESYS_TR.PCR20, session2=12.3
            )

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_policy(
                policy, TPM2_ALG.SHA256, ESYS_TR.PCR20, session3=object()
            )

    def test_pcr_set_auth_value(self):

        self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, b"password")
        self.ectx.tr_set_auth(ESYS_TR.PCR20, b"password")
        self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, "password")
        self.ectx.tr_set_auth(ESYS_TR.PCR20, "password")
        self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, TPM2B_DIGEST("password"))

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_value("bar", b"password")

        with self.assertRaises(ValueError):
            self.ectx.pcr_set_auth_value(42, b"password")

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, object())

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, b"password", session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, b"password", session2={})

        with self.assertRaises(TypeError):
            self.ectx.pcr_set_auth_value(ESYS_TR.PCR20, b"password", session3=43.2)

    def test_pcr_reset(self):

        self.ectx.pcr_reset(ESYS_TR.PCR16)

        with self.assertRaises(TypeError):
            self.ectx.pcr_reset(42.0)

        with self.assertRaises(ValueError):
            self.ectx.pcr_reset(42)

        with self.assertRaises(TypeError):
            self.ectx.pcr_reset(ESYS_TR.PCR20, session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.pcr_reset(ESYS_TR.PCR20, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.pcr_reset(ESYS_TR.PCR20, session3=45.6)

    def test_policy_signed(self):

        handle = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa:rsapss:null",
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            ),
        )[0]

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        nonce = self.ectx.trsess_get_nonce_tpm(session)

        sequence = self.ectx.hash_sequence_start(None, TPM2_ALG.SHA256)

        self.ectx.sequence_update(sequence, TPM2B_MAX_BUFFER(bytes(nonce)))

        # 10 year expiration
        expiration = -(10 * 365 * 24 * 60 * 60)
        expbytes = expiration.to_bytes(4, byteorder="big", signed=True)

        digest = self.ectx.sequence_complete(sequence, expbytes, ESYS_TR.OWNER)[0]

        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        hash_validation = TPMT_TK_HASHCHECK(
            tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER
        )

        signature = self.ectx.sign(handle, digest, scheme, hash_validation)

        timeout, policy_ticket = self.ectx.policy_signed(
            handle, session, nonce, b"", b"", expiration, signature
        )

        self.assertEqual(type(timeout), TPM2B_TIMEOUT)
        self.assertEqual(type(policy_ticket), TPMT_TK_AUTH)

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                "baz", session, nonce, b"", b"", expiration, signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, 56.6, nonce, b"", b"", expiration, signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, object(), b"", b"", expiration, signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, TPM2B_PUBLIC(), b"", expiration, signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, b"", [], expiration, signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, b"", b"", object(), signature
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, b"", b"", expiration, "signature"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, b"", b"", expiration, signature, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle,
                session,
                nonce,
                b"",
                b"",
                expiration,
                signature,
                session2=object(),
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_signed(
                handle, session, nonce, b"", b"", expiration, signature, session3=56.6
            )

    def test_hierarchy_control(self):
        self.ectx.hierarchy_control(
            ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_ENDORSEMENT, False
        )

        with self.assertRaises(ValueError):
            self.ectx.hierarchy_control(ESYS_TR.RH_NULL, ESYS_TR.RH_ENDORSEMENT, False)

        with self.assertRaises(ValueError):
            self.ectx.hierarchy_control(ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_NULL, False)

        with self.assertRaises(TypeError):
            self.ectx.hierarchy_control(
                ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_ENDORSEMENT, b"bad"
            )

        with self.assertRaises(TypeError):
            self.ectx.hierarchy_control(
                ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_ENDORSEMENT, False, session1=None
            )

        with self.assertRaises(TypeError):
            self.ectx.hierarchy_control(
                ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_ENDORSEMENT, False, session2=None
            )

        with self.assertRaises(TypeError):
            self.ectx.hierarchy_control(
                ESYS_TR.RH_ENDORSEMENT, ESYS_TR.RH_ENDORSEMENT, False, session3=None
            )

    def test_set_primary_policy(self):
        self.ectx.set_primary_policy(
            ESYS_TR.RH_ENDORSEMENT, b"\x00" * 32, TPM2_ALG.SHA256
        )

        with self.assertRaises(TypeError):
            self.ectx.set_primary_policy(
                ESYS_TR.RH_ENDORSEMENT, b"\x00" * 32, TPM2_ALG.SHA256, session1=None
            )

        with self.assertRaises(TypeError):
            self.ectx.set_primary_policy(
                ESYS_TR.RH_ENDORSEMENT, b"\x00" * 32, TPM2_ALG.SHA256, session2=None
            )

        with self.assertRaises(TypeError):
            self.ectx.set_primary_policy(
                ESYS_TR.RH_ENDORSEMENT, b"\x00" * 32, TPM2_ALG.SHA256, session3=None
            )

        with self.assertRaises(ValueError):
            self.ectx.set_primary_policy(ESYS_TR.NULL, b"\x00" * 32, TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.set_primary_policy(ESYS_TR.ENDORSEMENT, 123, TPM2_ALG.SHA256)

        with self.assertRaises(ValueError):
            self.ectx.set_primary_policy(
                ESYS_TR.ENDORSEMENT, b"\x00" * 32, TPM2_SE.TRIAL
            )

    def test_change_pps(self):
        self.ectx.change_pps()

        with self.assertRaises(TypeError):
            self.ectx.change_pps(session1=None)

        with self.assertRaises(TypeError):
            self.ectx.change_pps(session2=None)

        with self.assertRaises(TypeError):
            self.ectx.change_pps(session2=None)

        with self.assertRaises(ValueError):
            self.ectx.change_pps(auth_handle=ESYS_TR.RH_OWNER)

    def test_change_eps(self):
        self.ectx.change_eps()

        with self.assertRaises(TypeError):
            self.ectx.change_eps(session1=None)

        with self.assertRaises(TypeError):
            self.ectx.change_eps(session2=None)

        with self.assertRaises(TypeError):
            self.ectx.change_eps(session2=None)

        with self.assertRaises(ValueError):
            self.ectx.change_eps(auth_handle=ESYS_TR.RH_OWNER)

    def test_clear(self):
        self.ectx.clear(ESYS_TR.RH_LOCKOUT)

        with self.assertRaises(TypeError):
            self.ectx.clear(ESYS_TR.RH_LOCKOUT, session1=None)

        with self.assertRaises(TypeError):
            self.ectx.clear(ESYS_TR.RH_LOCKOUT, session2=None)

        with self.assertRaises(TypeError):
            self.ectx.clear(ESYS_TR.RH_LOCKOUT, session2=None)

        with self.assertRaises(ValueError):
            self.ectx.clear(auth_handle=ESYS_TR.RH_OWNER)

    def test_clearcontrol(self):
        self.ectx.clear_control(ESYS_TR.RH_LOCKOUT, True)
        self.ectx.clear_control(ESYS_TR.RH_PLATFORM, False)

        with self.assertRaises(TypeError):
            self.ectx.clear_control(ESYS_TR.RH_LOCKOUT, True, session1=None)

        with self.assertRaises(TypeError):
            self.ectx.clear_control(ESYS_TR.RH_LOCKOUT, True, session2=None)

        with self.assertRaises(TypeError):
            self.ectx.clear_control(ESYS_TR.RH_LOCKOUT, True, session3=None)

        with self.assertRaises(ValueError):
            self.ectx.clear_control(ESYS_TR.RH_OWNER, False)

        with self.assertRaises(TypeError):
            self.ectx.clear_control(ESYS_TR.RH_LOCKOUT, b"bad")

    def test_gettcti(self):
        tcti = self.ectx.get_tcti()
        self.assertTrue(isinstance(tcti, TCTI))

        self.assertEqual(tcti, self.ectx.tcti)

    def test_policy_secret(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        nonce = self.ectx.trsess_get_nonce_tpm(session)

        expiration = -(10 * 365 * 24 * 60 * 60)

        timeout, policyTicket = self.ectx.policy_secret(
            ESYS_TR.OWNER, session, nonce, b"", b"", expiration
        )
        self.assertTrue(type(timeout), TPM2B_TIMEOUT)
        self.assertTrue(type(policyTicket), TPMT_TK_AUTH)

        with self.assertRaises(TypeError):
            self.ectx.policy_secret("owner", session, nonce, b"", b"", expiration)

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(ESYS_TR.OWNER, 56.7, nonce, b"", b"", expiration)

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(
                ESYS_TR.OWNER, session, object(), b"", b"", expiration
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(
                ESYS_TR.OWNER, session, nonce, TPM2B_PUBLIC(), b"", expiration
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(ESYS_TR.OWNER, session, nonce, b"", {}, expiration)

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(ESYS_TR.OWNER, session, nonce, b"", b"", 42.2)

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(
                ESYS_TR.OWNER, session, nonce, b"", b"", expiration, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(
                ESYS_TR.OWNER, session, nonce, b"", b"", expiration, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_secret(
                ESYS_TR.OWNER, session, nonce, b"", b"", expiration, session3=56.7
            )

    def test_policy_ticket(self):
        handle = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa:rsapss:null",
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            ),
        )[0]

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        nonce = self.ectx.trsess_get_nonce_tpm(session)

        sequence = self.ectx.hash_sequence_start(None, TPM2_ALG.SHA256)

        self.ectx.sequence_update(sequence, TPM2B_MAX_BUFFER(bytes(nonce)))

        # 10 year expiration
        expiration = -(10 * 365 * 24 * 60 * 60)
        expbytes = expiration.to_bytes(4, byteorder="big", signed=True)

        digest = self.ectx.sequence_complete(sequence, expbytes, ESYS_TR.OWNER)[0]

        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        hash_validation = TPMT_TK_HASHCHECK(
            tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER
        )

        signature = self.ectx.sign(handle, digest, scheme, hash_validation)

        timeout, policy_ticket = self.ectx.policy_signed(
            handle, session, nonce, b"", b"", expiration, signature
        )

        self.ectx.flush_context(session)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        name = self.ectx.tr_get_name(handle)
        self.ectx.policy_ticket(session, timeout, b"", b"", name, policy_ticket)

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                "notasession", timeout, b"", b"", name, policy_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(session, object(), b"", b"", name, policy_ticket)

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                session, timeout, TPM2B_AUTH, b"", name, policy_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                session, timeout, b"", object(), name, policy_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(session, timeout, b"", b"", [], policy_ticket)

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(session, timeout, b"", b"", name, 42)

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                session, timeout, b"", b"", name, policy_ticket, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                session, timeout, b"", b"", name, policy_ticket, session2=56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_ticket(
                session, timeout, b"", b"", name, policy_ticket, session3=object()
            )

    def test_policy_or(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_or(
            session,
            TPML_DIGEST(
                [
                    b"0123456789ABCDEF0123456789ABCDEF",
                    b"0987654321ABCDEF1234567890ABCDEF",
                ]
            ),
        )

        self.ectx.policy_or(
            session,
            [b"0123456789ABCDEF0123456789ABCDEF", b"0987654321ABCDEF1234567890ABCDEF"],
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_or("bar", TPML_DIGEST())

        with self.assertRaises(TypeError):
            self.ectx.policy_or(session, TPML_PCR_SELECTION())

        with self.assertRaises(TypeError):
            self.ectx.policy_or(session, TPML_DIGEST(), session1=43.2)

        with self.assertRaises(TypeError):
            self.ectx.policy_or(session, TPML_DIGEST(), session2="bar")

        with self.assertRaises(TypeError):
            self.ectx.policy_or(session, TPML_DIGEST(), session3=object())

    def test_policy_pcr(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_pcr(session, b"0123456789ABCDEF0123456789ABCDEF", "sha256:1")
        self.ectx.policy_pcr(
            session, TPM2B_DIGEST(b"0123456789ABCDEF0123456789ABCDEF"), "sha256:1"
        )
        self.ectx.policy_pcr(
            session,
            b"0123456789ABCDEF0123456789ABCDEF",
            TPML_PCR_SELECTION.parse("sha256:1"),
        )
        self.ectx.policy_pcr(
            session,
            TPM2B_DIGEST(b"0123456789ABCDEF0123456789ABCDEF"),
            TPML_PCR_SELECTION.parse("sha256:1"),
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_pcr(session, TPM2B_ATTEST(), "sha256:1")

        with self.assertRaises(TypeError):
            self.ectx.policy_pcr(session, TPM2B_DIGEST(), TPML_ALG())

        with self.assertRaises(TypeError):
            self.ectx.policy_pcr(session, TPM2B_DIGEST(), "sha256:1", session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.policy_pcr(session, TPM2B_DIGEST(), "sha256:1", session2=42.2)

        with self.assertRaises(TypeError):
            self.ectx.policy_pcr(session, TPM2B_DIGEST(), "sha256:1", session3=object)

    def test_policy_locality(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_locality(session, TPMA_LOCALITY.ONE)

        with self.assertRaises(TypeError):
            self.ectx.policy_locality(45.6, TPMA_LOCALITY.ONE)

        with self.assertRaises(TypeError):
            self.ectx.policy_locality(session, "baz")

        with self.assertRaises(ValueError):
            self.ectx.policy_locality(session, 0)

        with self.assertRaises(ValueError):
            self.ectx.policy_locality(session, 256)

        with self.assertRaises(TypeError):
            self.ectx.policy_locality(session, TPMA_LOCALITY.ONE, session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.policy_locality(session, TPMA_LOCALITY.ONE, session2=56.7)

        with self.assertRaises(TypeError):
            self.ectx.policy_locality(session, TPMA_LOCALITY.ONE, session3=object())

    def test_policy_nv(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.nv_define_space(b"", nvpub)

        self.ectx.policy_nv(ESYS_TR.OWNER, nvhandle, session, b"12345678", TPM2_EO.EQ)

        self.ectx.policy_nv(
            ESYS_TR.OWNER, nvhandle, session, TPM2B_OPERAND(b"12345678"), TPM2_EO.EQ, 4
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(42.2, nvhandle, session, b"12345678", TPM2_EO.EQ)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(ESYS_TR.OWNER, "baz", session, b"12345678", TPM2_EO.EQ)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(
                ESYS_TR.OWNER, nvhandle, object(), b"12345678", TPM2_EO.EQ
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(ESYS_TR.OWNER, nvhandle, session, object, TPM2_EO.EQ)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(ESYS_TR.OWNER, nvhandle, session, b"12345678", "baz")

        with self.assertRaises(ValueError):
            self.ectx.policy_nv(ESYS_TR.OWNER, nvhandle, session, b"12345678", 42)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(
                ESYS_TR.OWNER, nvhandle, session, b"12345678", TPM2_EO.EQ, "baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(
                ESYS_TR.OWNER,
                nvhandle,
                session,
                b"12345678",
                TPM2_EO.EQ,
                session1="baz",
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(
                ESYS_TR.OWNER, nvhandle, session, b"12345678", TPM2_EO.EQ, session2=42.2
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_nv(
                ESYS_TR.OWNER,
                nvhandle,
                session,
                b"12345678",
                TPM2_EO.EQ,
                session3=object(),
            )

    def test_policy_counter_timer(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_counter_timer(session, b"12345678", TPM2_EO.EQ)
        self.ectx.policy_counter_timer(
            session, TPM2B_OPERAND(b"12345678"), TPM2_EO.EQ, 4
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(object, b"12345678", TPM2_EO.EQ)

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(session, TPM2B_ATTEST(), TPM2_EO.EQ)

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(session, b"12345678", 42.2)

        with self.assertRaises(ValueError):
            self.ectx.policy_counter_timer(session, b"12345678", 42)

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(session, b"12345678", TPM2_EO.EQ, "bar")

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(
                session, b"12345678", TPM2_EO.EQ, session1="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(
                session, b"12345678", TPM2_EO.EQ, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_counter_timer(
                session, b"12345678", TPM2_EO.EQ, session3=45.6
            )

    def test_policy_physical_presence(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_physical_presence(session)

        with self.assertRaises(TypeError):
            self.ectx.policy_physical_presence("session")

        with self.assertRaises(TypeError):
            self.ectx.policy_physical_presence(session, session1="bar")

        with self.assertRaises(TypeError):
            self.ectx.policy_physical_presence(session, session2=list())

        with self.assertRaises(TypeError):
            self.ectx.policy_physical_presence(session, session3=42.2)

    def test_policy_cp_hash(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_cp_hash(session, b"01234567890ABCDEF012345689ABCDEF")
        self.ectx.policy_cp_hash(
            session, TPM2B_DIGEST(b"01234567890ABCDEF012345689ABCDEF")
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_cp_hash(42.2, b"01234567890ABCDEF012345689ABCDEF")

        with self.assertRaises(TypeError):
            self.ectx.policy_cp_hash(session, TPM2B_ATTEST())

        with self.assertRaises(TypeError):
            self.ectx.policy_cp_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session1="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_cp_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_cp_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session3=45.6
            )

    def test_policy_name_hash(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_name_hash(session, b"01234567890ABCDEF012345689ABCDEF")

        self.ectx.policy_restart(session)

        self.ectx.policy_name_hash(
            session, TPM2B_DIGEST(b"ABCDEF01234567890ABCDEF012345689")
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_name_hash(42.2, b"01234567890ABCDEF012345689ABCDEF")

        with self.assertRaises(TypeError):
            self.ectx.policy_name_hash(session, TPM2B_ATTEST())

        with self.assertRaises(TypeError):
            self.ectx.policy_name_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session1="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_name_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_name_hash(
                session, b"01234567890ABCDEF012345689ABCDEF", session3=45.6
            )

    def test_policy_duplication_select(self):

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_duplication_select(
            session,
            b"0123456789ABCDEF0123456789ABCDEF",
            b"0123456789ABCDEF0123456789ABCDEF",
        )
        self.ectx.policy_restart(session)
        self.ectx.policy_duplication_select(
            session,
            TPM2B_NAME(b"0123456789ABCDEF0123456789ABCDEF"),
            TPM2B_NAME(b"0123456789ABCDEF0123456789ABCDEF"),
        )
        self.ectx.policy_restart(session)
        self.ectx.policy_duplication_select(
            session,
            TPM2B_NAME(b"0123456789ABCDEF0123456789ABCDEF"),
            b"0123456789ABCDEF0123456789ABCDEF",
            True,
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                42.2,
                b"0123456789ABCDEF0123456789ABCDEF",
                b"0123456789ABCDEF0123456789ABCDEF",
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session, TPM2B_ATTEST(), b"0123456789ABCDEF0123456789ABCDEF"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session, b"0123456789ABCDEF0123456789ABCDEF", object()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session,
                b"0123456789ABCDEF0123456789ABCDEF",
                b"0123456789ABCDEF0123456789ABCDEF",
                "nope",
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session,
                b"0123456789ABCDEF0123456789ABCDEF",
                b"0123456789ABCDEF0123456789ABCDEF",
                session1=42.5,
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session,
                b"0123456789ABCDEF0123456789ABCDEF",
                b"0123456789ABCDEF0123456789ABCDEF",
                session2="baz",
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_duplication_select(
                session,
                b"0123456789ABCDEF0123456789ABCDEF",
                b"0123456789ABCDEF0123456789ABCDEF",
                session3=object(),
            )

    def test_policy_authorize(self):

        handle = self.ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(),
            TPM2B_PUBLIC.parse(
                "rsa:rsapss:null",
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
            ),
        )[0]

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        check_ticket = TPMT_TK_VERIFIED(tag=TPM2_ST.VERIFIED, hierarchy=TPM2_RH.OWNER)
        name = self.ectx.tr_get_name(handle)

        self.ectx.policy_authorize(
            session, TPM2B_DIGEST(), TPM2B_NONCE(), name, check_ticket
        )
        self.ectx.policy_authorize(
            session, TPM2B_DIGEST(), TPM2B_NONCE(), name, check_ticket
        )
        self.ectx.policy_authorize(session, b"", TPM2B_NONCE(), name, check_ticket)
        self.ectx.policy_authorize(session, TPM2B_DIGEST(), b"", name, check_ticket)
        self.ectx.policy_authorize(
            session, TPM2B_DIGEST(), TPM2B_NONCE(), bytes(name), check_ticket
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                42.5, TPM2B_DIGEST(), TPM2B_NONCE(), name, check_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session, TPM2B_ATTEST(), TPM2B_NONCE(), name, check_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session, TPM2B_DIGEST(), object(), name, check_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session, TPM2B_DIGEST(), TPM2B_NONCE(), object(), check_ticket
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session, TPM2B_DIGEST(), TPM2B_NONCE(), name, TPM2B_AUTH()
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session,
                TPM2B_DIGEST(),
                TPM2B_NONCE(),
                name,
                check_ticket,
                session1="foo",
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session,
                TPM2B_DIGEST(),
                TPM2B_NONCE(),
                name,
                check_ticket,
                session2=42.4,
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize(
                session,
                TPM2B_DIGEST(),
                TPM2B_NONCE(),
                name,
                check_ticket,
                session3=object(),
            )

    def test_policy_password(self):

        sym = TPMT_SYM_DEF(TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_password(session)

        with self.assertRaises(TypeError):
            self.ectx.policy_password("session")

        with self.assertRaises(TypeError):
            self.ectx.policy_password(session, session1=45.6)

        with self.assertRaises(TypeError):
            self.ectx.policy_password(session, session2=object)

        with self.assertRaises(TypeError):
            self.ectx.policy_password(session, session3="baz")

    def test_policy_nv_written(self):

        sym = TPMT_SYM_DEF(TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_nv_written(session)
        self.ectx.policy_restart(session)
        self.ectx.policy_nv_written(session, False)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv_written(43.2)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv_written(session, "False")

        with self.assertRaises(TypeError):
            self.ectx.policy_nv_written(session, session1=45.6)

        with self.assertRaises(TypeError):
            self.ectx.policy_nv_written(session, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.policy_nv_written(session, session3="baz")

    def test_policy_template(self):

        sym = TPMT_SYM_DEF(TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_template(session, b"0123456789ABCDEF01234567890ABCDE")
        self.ectx.policy_template(
            session, TPM2B_DIGEST(b"0123456789ABCDEF01234567890ABCDE")
        )

        with self.assertRaises(TypeError):
            self.ectx.policy_template(object(), b"0123456789ABCDEF01234567890ABCDE")

        with self.assertRaises(TypeError):
            self.ectx.policy_template(session, list())

        with self.assertRaises(TypeError):
            self.ectx.policy_template(
                session, b"0123456789ABCDEF01234567890ABCDE", session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_template(
                session, b"0123456789ABCDEF01234567890ABCDE", session2=object
            )

        with self.assertRaises(TypeError):
            self.ectx.policy_template(
                session, b"0123456789ABCDEF01234567890ABCDE", session3=45.6
            )

    def test_policy_authorize_nv(self):

        nv_public = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=TPM2_HC.NV_INDEX_FIRST,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.parse("ownerread|ownerwrite|authread|authwrite"),
                dataSize=32,
            )
        )

        # No password NV index
        nv_index = self.ectx.nv_define_space(None, nv_public)

        sym = TPMT_SYM_DEF(TPM2_ALG.NULL)

        session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.TRIAL,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )

        self.ectx.policy_authorize_nv(nv_index, session)
        self.ectx.policy_authorize_nv(nv_index, session, auth_handle=ESYS_TR.OWNER)

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv("not an index", session)

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv(nv_index, object())

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv(nv_index, session, auth_handle=object)

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv(nv_index, session, session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv(nv_index, session, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.policy_authorize_nv(nv_index, session, session3=45.6)

    def test_esys_tr_functions(self):

        handle = self.ectx.create_primary(TPM2B_SENSITIVE_CREATE())[0]

        buffer = self.ectx.tr_serialize(handle)
        self.assertEqual(type(buffer), bytes)
        self.assertEqual(handle.serialize(self.ectx), buffer)

        handle2 = self.ectx.tr_deserialize(buffer)
        self.assertEqual(type(handle2), ESYS_TR)

        handle3 = ESYS_TR.deserialize(self.ectx, buffer)
        self.assertEqual(type(handle3), ESYS_TR)

        name2 = handle2.get_name(self.ectx)
        name3 = handle3.get_name(self.ectx)
        self.assertEqual(name2, name3)

        self.ectx.tr_close(handle2)
        handle3.close(self.ectx)

        with self.assertRaises(TypeError):
            self.ectx.tr_serialize("bad")

        with self.assertRaises(TSS2_Exception):
            self.ectx.tr_serialize(ESYS_TR(123456))

        with self.assertRaises(TypeError):
            self.ectx.tr_deserialize(42)

        with self.assertRaises(TSS2_Exception):
            self.ectx.tr_deserialize(b"0123456890")

    def test_ref_parent(self):
        # Test keeping a reference to the parent in a child structure
        _, pub, _, _, _ = self.ectx.create_primary(None, "ecc")
        pa = pub.publicArea
        del pub
        gc.collect()
        self.assertEqual(pa.type, TPM2_ALG.ECC)
        self.assertEqual(
            pa.objectAttributes, TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        )

        # Test keeping a reference to the parent in an element from a TPML_OBJECT
        _, sels, _ = self.ectx.pcr_read("sha256:16")
        sel = sels[0]
        del sels
        gc.collect()
        self.assertEqual(sel.hash, TPM2_ALG.SHA256)
        self.assertEqual(bytes(sel.pcrSelect), b"\x00\x00\x01\x00")

        # Test keeping a reference to the parent when accessing a TPM2_SIMPLE_OBJECT buffer
        handle, _, _, _, _ = self.ectx.create_primary(None, "ecc")
        _, name, _ = self.ectx.read_public(handle)
        algb = name.name[0:2]
        del name
        gc.collect()
        self.assertEqual(bytes(algb), TPM2_ALG.SHA256.to_bytes(2, "big"))

    def test_double_close(self):

        # Shutdown the old TCTI connection so we can connect with a name-conf string
        # without blocking
        tcti = self.ectx.tcti
        self.ectx.close()
        if tcti is not None:
            tcti.close()

        ectx = ESAPI(self.tpm.tcti_name_conf)
        self.assertTrue(ectx._did_load_tcti)
        self.assertTrue(ectx._ctx)
        self.assertTrue(ectx._ctx_pp)
        self.assertEqual(ectx.tcti.name_conf, self.tpm.tcti_name_conf)
        ectx.close()
        self.assertFalse(ectx._ctx)
        self.assertFalse(ectx._ctx_pp)
        self.assertEqual(ectx.tcti, None)
        ectx.close()
        self.assertFalse(ectx._ctx)
        self.assertFalse(ectx._ctx_pp)
        self.assertEqual(ectx.tcti, None)


if __name__ == "__main__":
    unittest.main()
