#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""

import unittest

from tpm2_pytss import *
from .TSS2_BaseTest import TSS2_EsapiTest


class TestEsys(TSS2_EsapiTest):
    def testGetRandom(self):
        r = self.ectx.GetRandom(5)
        self.assertEqual(len(r), 5)

        with self.assertRaises(TypeError):
            self.ectx.GetRandom("foo")

        with self.assertRaises(TypeError):
            self.ectx.GetRandom(5, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.GetRandom(5, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.GetRandom(5, session3=56.7)

    def testCreatePrimary(self):
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

        handle, public, creation_data, digest, ticket = self.ectx.CreatePrimary(
            inSensitive, inPublic, ESYS_TR.OWNER, outsideInfo, creationPCR,
        )
        self.assertNotEqual(handle, 0)
        self.assertEqual(type(public), TPM2B_PUBLIC)
        self.assertEqual(type(creation_data), TPM2B_CREATION_DATA)
        self.assertEqual(type(digest), TPM2B_DIGEST)
        self.assertEqual(type(ticket), TPMT_TK_CREATION)
        self.ectx.FlushContext(handle)

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive,)
        self.assertNotEqual(handle, 0)
        self.ectx.FlushContext(handle)

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)
        self.assertNotEqual(handle, 0)
        self.ectx.FlushContext(handle)

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, "ecc256")
        self.assertNotEqual(handle, 0)
        self.ectx.FlushContext(handle)

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "ecc256", creationPCR="sha256:4,6,7"
        )
        self.assertNotEqual(handle, 0)
        self.ectx.FlushContext(handle)

        with self.assertRaises(TypeError):
            self.ectx.CreatePrimary(
                TPM2B_DATA, inPublic, ESYS_TR.OWNER, outsideInfo, creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.CreatePrimary(
                inSensitive,
                b"should not work",
                ESYS_TR.OWNER,
                outsideInfo,
                creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.CreatePrimary(
                inSensitive, inPublic, object(), outsideInfo, creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.CreatePrimary(
                inSensitive, inPublic, ESYS_TR.OWNER, object(), creationPCR,
            )

        with self.assertRaises(TypeError):
            self.ectx.CreatePrimary(
                inSensitive, inPublic, ESYS_TR.OWNER, outsideInfo, TPM2B_SENSITIVE(),
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.CreatePrimary(
                inSensitive, "ecc256", session1=object()
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.CreatePrimary(
                inSensitive, "ecc256", session2=object()
            )

        with self.assertRaises(TypeError):
            handle, _, _, _, _ = self.ectx.CreatePrimary(
                inSensitive, "ecc256", session3=object()
            )

    def testPCRRead(self):

        pcrsels = TPML_PCR_SELECTION.parse("sha1:3+sha256:all")
        _, _, digests, = self.ectx.PCR_Read(pcrsels)

        self.assertEqual(len(digests[0]), 20)

        for d in digests[1:]:
            self.assertEqual(len(d), 32)

    def test_plain_NV_define_write_read_undefine(self):

        nv_public = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=TPM2_HC.NV_INDEX_FIRST,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.parse("ownerread|ownerwrite|authread|authwrite"),
                dataSize=32,
            )
        )

        # No password NV index
        nv_index = self.ectx.NV_DefineSpace(None, nv_public)
        self.ectx.NV_Write(nv_index, b"hello world")

        value = self.ectx.NV_Read(nv_index, 11)
        self.assertEqual(bytes(value), b"hello world")

        public, name = self.ectx.NV_ReadPublic(nv_index)
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

        self.ectx.NV_UndefineSpace(nv_index)

        with self.assertRaises(TSS2_Exception):
            public, name = self.ectx.NV_ReadPublic(nv_index)

    def test_hierarchychangeauth(self):

        self.ectx.HierarchyChangeAuth(ESYS_TR.OWNER, "passwd")

        # force esys to forget about the 'good' password
        self.ectx.setAuth(ESYS_TR.OWNER, "badpasswd")

        with self.assertRaises(TSS2_Exception):
            self.ectx.HierarchyChangeAuth(ESYS_TR.OWNER, "anotherpasswd")

    def test_fulltest_YES(self):
        self.ectx.SelfTest(True)

    def test_fulltest_NO(self):
        self.ectx.SelfTest(False)

    def test_incremental_self_test(self):
        algs = TPML_ALG.parse("rsa,ecc,xor,aes,cbc")

        self.ectx.IncrementalSelfTest(algs)

        self.ectx.IncrementalSelfTest("rsa,ecc,xor,aes,cbc")

        with self.assertRaises(TypeError):
            self.ectx.IncrementalSelfTest(None)
        with self.assertRaises(TypeError):
            self.ectx.IncrementalSelfTest(object())

        with self.assertRaises(TypeError):
            self.ectx.IncrementalSelfTest(session1=45.9)

        with self.assertRaises(TypeError):
            self.ectx.IncrementalSelfTest(session2=object())

        with self.assertRaises(TypeError):
            self.ectx.IncrementalSelfTest(session3=TPM2B_PUBLIC())

    def test_incremental_resume_test(self):
        algs = TPML_ALG.parse("rsa,ecc,xor,aes,cbc")

        self.ectx.IncrementalSelfTest(algs)
        toDo, rc = self.ectx.GetTestResult()
        self.assertEqual(type(toDo), TPM2B_MAX_BUFFER)
        self.assertEqual(rc, TPM2_RC.SUCCESS)

        with self.assertRaises(TypeError):
            self.ectx.GetTestResult(session1=45.7)

        with self.assertRaises(TypeError):
            self.ectx.GetTestResult(session2=TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.GetTestResult(session3=object())

    def test_hmac_session(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        hmac_session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.HMAC,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )
        self.assertTrue(hmac_session)
        self.ectx.HierarchyChangeAuth(ESYS_TR.OWNER, "passwd", session1=hmac_session)

        # force esys to forget about the 'good' password
        self.ectx.setAuth(ESYS_TR.OWNER, "badpasswd")

        with self.assertRaises(TSS2_Exception):
            self.ectx.HierarchyChangeAuth(
                ESYS_TR.OWNER, "anotherpasswd", session1=hmac_session
            )

        # test some bad params
        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                object, ESYS_TR.NONE, None, TPM2_SE.HMAC, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, object(), None, TPM2_SE.HMAC, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE,
                ESYS_TR.NONE,
                TPM2B_PUBLIC(),
                TPM2_SE.HMAC,
                sym,
                TPM2_ALG.SHA256,
            )

        with self.assertRaises(ValueError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, ESYS_TR.NONE, None, 8745635, sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, ESYS_TR.NONE, None, object(), sym, TPM2_ALG.SHA256
            )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, ESYS_TR.NONE, None, TPM2_SE.HMAC, 42, TPM2_ALG.SHA256
            )

        with self.assertRaises(ValueError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, ESYS_TR.NONE, None, TPM2_SE.HMAC, sym, 8395847
            )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                ESYS_TR.NONE, ESYS_TR.NONE, None, TPM2_SE.HMAC, sym, TPM2B_SYM_KEY()
            )

    def test_start_authSession_enckey(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=handle,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.TRSess_SetAttributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.GetRandom(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_start_authSession_enckey_bindkey(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=handle,
            bind=handle,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.TRSess_SetAttributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.GetRandom(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_TRSess_SetAttributes(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=handle,
            bind=handle,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.TRSess_SetAttributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        with self.assertRaises(TypeError):
            self.ectx.TRSess_SetAttributes(
                object(), (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
            )

        with self.assertRaises(TypeError):
            self.ectx.TRSess_SetAttributes(session, 67.5)

    def test_start_authSession_noncecaller(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, "rsa2048:aes128cfb")

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=handle,
            bind=handle,
            nonceCaller=TPM2B_NONCE(b"thisisthirtytwocharslastichecked"),
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.TRSess_SetAttributes(
            session, (TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )

        random = self.ectx.GetRandom(4, session1=session)
        self.assertEqual(len(random), 4)

    def test_start_authSession_noncecaller_bad(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        with self.assertRaises(TypeError):
            self.ectx.StartAuthSession(
                tpmKey=ESYS_TR.NONE,
                bind=ESYS_TR.NONE,
                nonceCaller=object(),
                sessionType=TPM2_SE.HMAC,
                symmetric=sym,
                authHash=TPM2_ALG.SHA256,
            )

    def test_create(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        alg = "rsa2048"
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg))
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, outsideInfo
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, creationPCR=creationPCR
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle,
            childInSensitive,
            childInPublic,
            creationPCR="sha256:1,2,3,4,5",
        )
        self.assertEqual(type(priv), TPM2B_PRIVATE),
        self.assertEqual(type(pub), TPM2B_PUBLIC),

        with self.assertRaises(TypeError):
            self.ectx.Create(
                34.945, childInSensitive, childInPublic, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.Create(
                parentHandle, object(), childInPublic, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.Create(
                parentHandle, childInSensitive, 56, outsideInfo, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.Create(
                parentHandle, childInSensitive, childInPublic, None, creationPCR
            )

        with self.assertRaises(TypeError):
            self.ectx.Create(
                parentHandle, childInSensitive, childInPublic, outsideInfo, object
            )

    def test_load(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.Create(parentHandle, childInSensitive)

        childHandle = self.ectx.Load(parentHandle, priv, pub)
        self.assertTrue(childHandle)

        with self.assertRaises(TypeError):
            self.ectx.Load(42.5, priv, pub)

        with self.assertRaises(TypeError):
            self.ectx.Load(parentHandle, TPM2B_DATA(), pub)

        with self.assertRaises(TypeError):
            self.ectx.Load(parentHandle, priv, object())

    def test_readpublic(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        priv, pub, _, _, _ = self.ectx.Create(parentHandle, childInSensitive)

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        pubdata, name, qname = self.ectx.ReadPublic(childHandle)
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
            self.ectx.ReadPublic(object())

        with self.assertRaises(TypeError):
            self.ectx.ReadPublic(childHandle, session1=object)

        with self.assertRaises(TypeError):
            self.ectx.ReadPublic(childHandle, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.ReadPublic(childHandle, session3=42.5)

    def test_MakeCredential(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
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

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        primaryKeyName = self.ectx.ReadPublic(parentHandle)[1]

        credential = TPM2B_DIGEST("this is my credential")

        # this can be done without a key as in tpm2-tools project, but for simpplicity
        # use the TPM command, which uses the PUBLIC portion of the object and thus
        # needs no auth.
        credentialBlob, secret = self.ectx.MakeCredential(
            childHandle, credential, primaryKeyName
        )
        self.assertEqual(type(credentialBlob), TPM2B_ID_OBJECT)
        self.assertEqual(type(secret), TPM2B_ENCRYPTED_SECRET)

        credentialBlob, secret = self.ectx.MakeCredential(
            childHandle, "this is my credential", bytes(primaryKeyName)
        )
        self.assertEqual(type(credentialBlob), TPM2B_ID_OBJECT)
        self.assertEqual(type(secret), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(42.5, credential, primaryKeyName)

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(childHandle, object(), primaryKeyName)

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(childHandle, credential, object())

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(
                childHandle, credential, primaryKeyName, session1="bar"
            )

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(
                childHandle, credential, primaryKeyName, session2=54.6
            )

        with self.assertRaises(TypeError):
            self.ectx.MakeCredential(
                childHandle, credential, primaryKeyName, session3=object()
            )

    def test_ActivateCredential(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
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

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        primaryKeyName = self.ectx.ReadPublic(parentHandle)[1]

        credential = TPM2B_DIGEST("this is my credential")

        # this can be done without a key as in tpm2-tools project, but for simpplicity
        # use the TPM command, which uses the PUBLIC portion of the object and thus
        # needs no auth.
        credentialBlob, secret = self.ectx.MakeCredential(
            childHandle, credential, primaryKeyName
        )

        self.ectx.setAuth(childHandle, "childpassword")

        certInfo = self.ectx.ActivateCredential(
            parentHandle, childHandle, credentialBlob, secret
        )
        self.assertEqual(bytes(certInfo), b"this is my credential")

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(object(), childHandle, credentialBlob, secret)

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(parentHandle, 76.4, credentialBlob, secret)

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(
                parentHandle, childHandle, TPM2B_PUBLIC(), secret
            )

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(
                parentHandle, childHandle, credentialBlob, object()
            )

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(
                parentHandle, childHandle, credentialBlob, secret, session1="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(
                parentHandle, childHandle, credentialBlob, secret, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.ActivateCredential(
                parentHandle, childHandle, credentialBlob, secret, session3=65.4
            )

    def test_unseal(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
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

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        self.ectx.setAuth(childHandle, "childpassword")

        secret = self.ectx.Unseal(childHandle)
        self.assertEqual(bytes(secret), b"sealedsecret")

        with self.assertRaises(TypeError):
            self.ectx.Unseal(45.2)

        with self.assertRaises(TypeError):
            self.ectx.Unseal(childHandle, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.Unseal(childHandle, session2=67.4)

        with self.assertRaises(TypeError):
            self.ectx.Unseal(childHandle, session3="bar")

    def test_objectChangeAuth(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
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

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        # force an error
        self.ectx.setAuth(childHandle, "BADchildpassword")

        with self.assertRaises(TSS2_Exception):
            self.ectx.ObjectChangeAuth(childHandle, parentHandle, "newauth")

        self.ectx.setAuth(childHandle, "childpassword")

        self.ectx.ObjectChangeAuth(childHandle, parentHandle, TPM2B_AUTH("newauth"))

        self.ectx.ObjectChangeAuth(childHandle, parentHandle, b"anotherauth")

        self.ectx.ObjectChangeAuth(childHandle, parentHandle, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.ObjectChangeAuth("bad", parentHandle, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.ObjectChangeAuth(childHandle, 56.7, "yetanotherone")

        with self.assertRaises(TypeError):
            self.ectx.ObjectChangeAuth(childHandle, parentHandle, object())

    def test_createloaded(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.Marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, priv, pub = self.ectx.CreateLoaded(
            parentHandle, childInSensitive, childInPublic
        )
        self.assertNotEqual(childHandle, 0)
        self.assertEqual(type(priv), TPM2B_PRIVATE)
        self.assertEqual(type(pub), TPM2B_PUBLIC)

        childHandle, priv, pub = self.ectx.CreateLoaded(parentHandle, childInSensitive)
        self.assertNotEqual(childHandle, 0)
        self.assertEqual(type(priv), TPM2B_PRIVATE)
        self.assertEqual(type(pub), TPM2B_PUBLIC)

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(65.4, childInSensitive, childInPublic)

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(parentHandle, "1223", childInPublic)

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(parentHandle, childInSensitive, object())

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(parentHandle, childInSensitive, session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(parentHandle, childInSensitive, session2=b"baz")

        with self.assertRaises(TypeError):
            self.ectx.CreateLoaded(parentHandle, childInSensitive, session3=object())

    def test_rsa_enc_dec(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.Marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, _, _ = self.ectx.CreateLoaded(
            parentHandle, childInSensitive, childInPublic
        )

        message = TPM2B_PUBLIC_KEY_RSA("hello world")
        scheme = TPMT_RSA_DECRYPT(scheme=TPM2_ALG.RSAES)
        outData = self.ectx.RSA_Encrypt(childHandle, message, scheme)

        message2 = self.ectx.RSA_Decrypt(childHandle, outData, scheme)

        self.assertEqual(bytes(message), bytes(message2))

        outData = self.ectx.RSA_Encrypt(childHandle, "hello world", scheme)

        message2 = self.ectx.RSA_Decrypt(childHandle, outData, scheme)

        self.assertEqual(bytes(message), bytes(message2))

        # negative test RSA_Encrypt
        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(45.6, message, scheme)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(childHandle, TPM2B_PUBLIC(), scheme)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(childHandle, message, "foo")

        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(childHandle, message, scheme, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(childHandle, message, scheme, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.RSA_Encrypt(childHandle, message, scheme, session3=52.6)

        # negative test RSA_Decrypt
        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(56.2, outData, scheme)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(childHandle, object(), scheme)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(childHandle, outData, TPM2_ALG.RSAES)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(childHandle, outData, scheme, session1=67.9)

        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(childHandle, outData, scheme, session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.RSA_Decrypt(childHandle, outData, scheme, session3=object())

    def test_rsa_enc_dec_with_label(self):

        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "rsa2048:aes128cfb"
        )

        templ = TPMT_PUBLIC.parse(
            alg="rsa2048", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        )
        childInPublic = TPM2B_TEMPLATE(templ.Marshal())
        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        childHandle, _, _ = self.ectx.CreateLoaded(
            parentHandle, childInSensitive, childInPublic
        )

        message = TPM2B_PUBLIC_KEY_RSA("hello world")
        scheme = TPMT_RSA_DECRYPT(scheme=TPM2_ALG.RSAES)
        outData = self.ectx.RSA_Encrypt(
            childHandle, message, scheme, label=b"my label\0"
        )

        message2 = self.ectx.RSA_Decrypt(
            childHandle, outData, scheme, label=b"my label\0"
        )

        self.assertEqual(bytes(message), bytes(message2))

    def test_ECDH_KeyGen(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            inSensitive, "ecc256:aes128cfb"
        )

        zPoint, pubPoint = self.ectx.ECDH_KeyGen(parentHandle)
        self.assertNotEqual(zPoint, None)
        self.assertNotEqual(pubPoint, None)

        with self.assertRaises(TypeError):
            self.ectx.ECDH_KeyGen(56.8)

        with self.assertRaises(TypeError):
            self.ectx.ECDH_KeyGen(parentHandle, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.ECDH_KeyGen(parentHandle, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ECDH_KeyGen(parentHandle, session3=45.6)

    def test_ECDH_ZGen(self):

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

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

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

        outPoint = self.ectx.ECDH_ZGen(parentHandle, inPoint)
        self.assertEqual(type(outPoint), TPM2B_ECC_POINT)

        with self.assertRaises(TypeError):
            self.ectx.ECDH_ZGen(object(), inPoint)

        with self.assertRaises(TypeError):
            self.ectx.ECDH_ZGen(parentHandle, "boo")

        with self.assertRaises(TypeError):
            self.ectx.ECDH_ZGen(parentHandle, inPoint, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.ECDH_ZGen(parentHandle, inPoint, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ECDH_ZGen(parentHandle, inPoint, session3=89.6)

    def test_ECC_Parameters(self):

        params = self.ectx.ECC_Parameters(TPM2_ECC_CURVE.NIST_P256)
        self.assertEqual(type(params), TPMS_ALGORITHM_DETAIL_ECC)

        with self.assertRaises(ValueError):
            self.ectx.ECC_Parameters(42)

        with self.assertRaises(TypeError):
            self.ectx.ECC_Parameters(TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.ECC_Parameters(TPM2_ECC_CURVE.NIST_P256, session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.ECC_Parameters(TPM2_ECC_CURVE.NIST_P256, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.ECC_Parameters(TPM2_ECC_CURVE.NIST_P256, session3=TPM2B_DATA())

    def test_ZGen_2Phase(self):

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

        eccHandle, outPublic, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        curveId = TPM2_ECC.NIST_P256

        Q, counter = self.ectx.EC_Ephemeral(curveId)

        inQsB = TPM2B_ECC_POINT(outPublic.publicArea.unique.ecc)
        inQeB = Q
        Z1, Z2 = self.ectx.ZGen_2Phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter)
        self.assertEqual(type(Z1), TPM2B_ECC_POINT)
        self.assertEqual(type(Z2), TPM2B_ECC_POINT)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(42.5, inQsB, inQeB, TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(eccHandle, "hello", inQeB, TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(eccHandle, inQsB, object(), TPM2_ALG.ECDH, counter)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(eccHandle, inQsB, inQeB, object(), counter)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, "baz")

        with self.assertRaises(ValueError):
            self.ectx.ZGen_2Phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, 2 ** 18)

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session2="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.ZGen_2Phase(
                eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter, session3=45.5
            )

    def test_EncryptDecrypt(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()
        parentHandle = self.ectx.CreatePrimary(inSensitive, "ecc")[0]

        inPublic = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(alg="aes").Marshal())
        aesKeyHandle = self.ectx.CreateLoaded(parentHandle, inSensitive, inPublic)[0]

        ivIn = TPM2B_IV(b"thisis16byteszxc")
        inData = TPM2B_MAX_BUFFER(b"this is data to encrypt")
        outCipherText, outIV = self.ectx.EncryptDecrypt(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )
        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.EncryptDecrypt(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(bytes(inData), bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        # test plain bytes for data
        ivIn = b"thisis16byteszxc"
        inData = b"this is data to encrypt"
        outCipherText, outIV = self.ectx.EncryptDecrypt(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )
        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.EncryptDecrypt(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(inData, bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(42.5, True, TPM2_ALG.CFB, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, object(), TPM2_ALG.CFB, ivIn, outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, object(), ivIn, outCipherText)

        with self.assertRaises(ValueError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, 42, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, TPM2B_PUBLIC(), outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, None)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session3=12.3
            )

    def test_EncryptDecrypt2(self):

        inSensitive = TPM2B_SENSITIVE_CREATE()
        parentHandle = self.ectx.CreatePrimary(inSensitive, "ecc")[0]

        inPublic = TPM2B_TEMPLATE(TPMT_PUBLIC.parse(alg="aes").Marshal())
        aesKeyHandle = self.ectx.CreateLoaded(parentHandle, inSensitive, inPublic)[0]

        ivIn = TPM2B_IV(b"thisis16byteszxc")
        inData = TPM2B_MAX_BUFFER(b"this is data to encrypt")
        outCipherText, outIV = self.ectx.EncryptDecrypt2(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )

        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.EncryptDecrypt2(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(bytes(inData), bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        ivIn = b"thisis16byteszxc"
        inData = b"this is data to encrypt"
        outCipherText, outIV = self.ectx.EncryptDecrypt2(
            aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData
        )

        self.assertEqual(len(outIV), len(ivIn))

        outData, outIV2 = self.ectx.EncryptDecrypt2(
            aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText
        )
        self.assertEqual(inData, bytes(outData))
        self.assertEqual(bytes(outIV), bytes(outIV2))

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(42.5, True, TPM2_ALG.CFB, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, object(), TPM2_ALG.CFB, ivIn, outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, object(), ivIn, outCipherText)

        with self.assertRaises(ValueError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, 42, ivIn, outCipherText)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, TPM2B_PUBLIC(), outCipherText
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, None)

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session1=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.EncryptDecrypt(
                aesKeyHandle, True, TPM2_ALG.CFB, ivIn, outCipherText, session3=12.3
            )

    def test_Hash(self):

        # Null hierarchy default
        digest, ticket = self.ectx.Hash(b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Owner hierarchy set
        digest, ticket = self.ectx.Hash(b"1234", TPM2_ALG.SHA256, ESYS_TR.OWNER)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Test TPM2B_MAX_BUFFER
        inData = TPM2B_MAX_BUFFER(b"1234")
        digest, ticket = self.ectx.Hash(inData, TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        # Test str input
        inData = TPM2B_MAX_BUFFER("1234")
        digest, ticket = self.ectx.Hash(inData, TPM2_ALG.SHA256)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)
        d = bytes(digest)
        c = binascii.unhexlify(
            "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )
        self.assertEqual(c, d)

        with self.assertRaises(TypeError):
            self.ectx.Hash(object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.Hash(inData, "baz")

        with self.assertRaises(ValueError):
            self.ectx.Hash(inData, 42)

        with self.assertRaises(TypeError):
            self.ectx.Hash(inData, TPM2_ALG.SHA256, session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.Hash(inData, TPM2_ALG.SHA256, session2="baz")

        with self.assertRaises(TypeError):
            self.ectx.Hash(inData, TPM2_ALG.SHA256, session3=object())

    def test_HMAC(self):

        attrs = (
            TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        templ = TPMT_PUBLIC.parse(alg="hmac", objectAttributes=attrs)
        inPublic = TPM2B_PUBLIC(templ)

        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        primaryHandle = self.ectx.CreatePrimary(inSensitive, inPublic)[0]

        # Test bytes
        hmac = self.ectx.HMAC(primaryHandle, b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        # Test str
        hmac = self.ectx.HMAC(primaryHandle, "1234", TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        # Test Native
        inData = TPM2B_MAX_BUFFER("1234")
        hmac = self.ectx.HMAC(primaryHandle, inData, TPM2_ALG.SHA256)
        self.assertNotEqual(hmac, None)
        self.assertEqual(len(bytes(hmac)), 32)

        with self.assertRaises(TypeError):
            self.ectx.HMAC(45.6, inData, TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.HMAC(primaryHandle, object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.HMAC(primaryHandle, inData, "baz")

        with self.assertRaises(ValueError):
            self.ectx.HMAC(primaryHandle, inData, 42)

        with self.assertRaises(TypeError):
            self.ectx.HMAC(primaryHandle, inData, TPM2_ALG.SHA256, session1=object())

        with self.assertRaises(TypeError):
            self.ectx.HMAC(primaryHandle, inData, TPM2_ALG.SHA256, session2="object")

        with self.assertRaises(TypeError):
            self.ectx.HMAC(primaryHandle, inData, TPM2_ALG.SHA256, session3=45.6)

    def test_StirRandom(self):

        self.ectx.StirRandom(b"1234")
        self.ectx.StirRandom("1234")
        self.ectx.StirRandom(TPM2B_SENSITIVE_DATA("1234"))

        with self.assertRaises(TypeError):
            self.ectx.StirRandom(object())

        with self.assertRaises(TypeError):
            self.ectx.StirRandom("1234", session1=56.7)

        with self.assertRaises(TypeError):
            self.ectx.StirRandom("1234", session2="foo")

        with self.assertRaises(TypeError):
            self.ectx.StirRandom("1234", session3=object())

    def test_HMAC_Sequence(self):

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

        handle = self.ectx.CreatePrimary(inSensitive, inPublic)[0]

        seqHandle = self.ectx.HMAC_Start(handle, None, TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HMAC_Start(handle, b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HMAC_Start(handle, "1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HMAC_Start(handle, TPM2B_AUTH(b"1234"), TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)

        # self.ectx.setAuth(seqHandle, b"1234")

        self.ectx.SequenceUpdate(seqHandle, "here is some data")

        self.ectx.SequenceUpdate(seqHandle, b"more data but byte string")

        self.ectx.SequenceUpdate(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.SequenceUpdate(seqHandle, None)

        digest, ticket = self.ectx.SequenceComplete(seqHandle, None)
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)

        self.assertEqual(len(digest), 32)

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(45.6, "1234", TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(handle, dict(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(handle, "1234", object())

        with self.assertRaises(ValueError):
            self.ectx.HMAC_Start(handle, "1234", 42)

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(handle, "1234", TPM2_ALG.SHA256, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(handle, "1234", TPM2_ALG.SHA256, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.HMAC_Start(handle, "1234", TPM2_ALG.SHA256, session3=45.6)

    def test_HashSequence(self):

        seqHandle = self.ectx.HashSequenceStart(None, TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HashSequenceStart(b"1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HashSequenceStart("1234", TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)
        self.ectx.FlushContext(seqHandle)

        seqHandle = self.ectx.HashSequenceStart(TPM2B_AUTH(b"1234"), TPM2_ALG.SHA256)
        self.assertNotEqual(seqHandle, 0)

        self.ectx.setAuth(seqHandle, b"1234")

        self.ectx.SequenceUpdate(seqHandle, "here is some data")

        self.ectx.SequenceUpdate(seqHandle, b"more data but byte string")

        self.ectx.SequenceUpdate(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.SequenceUpdate(seqHandle, None)

        digest, ticket = self.ectx.SequenceComplete(seqHandle, "AnotherBuffer")
        self.assertNotEqual(digest, None)
        self.assertNotEqual(ticket, None)

        e = binascii.unhexlify(
            "a02271d78e351c6e9e775b0570b440d3ac37ad6c02a3b69df940f3f893f80d41"
        )
        d = bytes(digest)
        self.assertEqual(e, d)

        with self.assertRaises(TypeError):
            self.ectx.HashSequenceStart(object(), TPM2_ALG.SHA256)

        with self.assertRaises(TypeError):
            self.ectx.HashSequenceStart(b"1234", "dssdf")

        with self.assertRaises(ValueError):
            self.ectx.HashSequenceStart(b"1234", 42)

        with self.assertRaises(TypeError):
            self.ectx.HashSequenceStart(b"1234", TPM2_ALG.SHA256, session1="baz")

        with self.assertRaises(TypeError):
            self.ectx.HashSequenceStart(b"1234", TPM2_ALG.SHA256, session2=56.7)

        with self.assertRaises(TypeError):
            self.ectx.HashSequenceStart(b"1234", TPM2_ALG.SHA256, session3=TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.SequenceUpdate(56.7, "here is some data")

        with self.assertRaises(TypeError):
            self.ectx.SequenceUpdate(seqHandle, [])

        with self.assertRaises(TypeError):
            self.ectx.SequenceUpdate(seqHandle, "here is some data", sequence1="foo")

        with self.assertRaises(TypeError):
            self.ectx.SequenceUpdate(seqHandle, "here is some data", sequence2=object())

        with self.assertRaises(TypeError):
            self.ectx.SequenceUpdate(seqHandle, "here is some data", sequence3=78.23)

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(78.25, "AnotherBuffer")

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(seqHandle, [])

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(seqHandle, "AnotherBuffer", hierarchy=object())

        with self.assertRaises(ValueError):
            self.ectx.SequenceComplete(seqHandle, "AnotherBuffer", hierarchy=42)

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(seqHandle, "AnotherBuffer", session1=42.67)

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(seqHandle, "AnotherBuffer", session2="baz")

        with self.assertRaises(TypeError):
            self.ectx.SequenceComplete(seqHandle, "AnotherBuffer", session3=object())

    def test_EventSequenceComplete(self):

        seqHandle = self.ectx.HashSequenceStart(TPM2B_AUTH(b"1234"), TPM2_ALG.NULL)
        self.assertNotEqual(seqHandle, 0)

        self.ectx.setAuth(seqHandle, b"1234")

        self.ectx.SequenceUpdate(seqHandle, "here is some data")

        self.ectx.SequenceUpdate(seqHandle, b"more data but byte string")

        self.ectx.SequenceUpdate(seqHandle, TPM2B_MAX_BUFFER("native data format"))

        self.ectx.SequenceUpdate(seqHandle, None)

        pcrs = self.ectx.EventSequenceComplete(
            ESYS_TR.PCR16, seqHandle, "AnotherBuffer"
        )
        self.assertEqual(type(pcrs), TPML_DIGEST_VALUES)

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(object(), seqHandle, None)

        with self.assertRaises(ValueError):
            self.ectx.EventSequenceComplete(42, seqHandle, None)

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(ESYS_TR.PCR16, 46.5, None)

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(ESYS_TR.PCR16, seqHandle, object())

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(
                ESYS_TR.PCR16, seqHandle, None, sequence1=67.34
            )

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(
                ESYS_TR.PCR16, seqHandle, None, sequence2="boo"
            )

        with self.assertRaises(TypeError):
            self.ectx.EventSequenceComplete(
                ESYS_TR.PCR16, seqHandle, None, sequence3=object()
            )

    def test_ContextSave_ContextLoad(self):
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

        handle, outpub, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        ctx = self.ectx.ContextSave(handle)

        nhandle = self.ectx.ContextLoad(ctx)
        name = self.ectx.TR_GetName(nhandle)

        self.assertEqual(bytes(outpub.getName()), bytes(name))

    def test_FlushContext(self):
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

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        self.ectx.FlushContext(handle)
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.TR_GetName(handle)
        self.assertEqual(e.exception.error, lib.TSS2_ESYS_RC_BAD_TR)

    def test_EvictControl(self):
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

        handle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        self.ectx.EvictControl(
            ESYS_TR.OWNER, handle, 0x81000081, session1=ESYS_TR.PASSWORD
        )
        phandle = self.ectx.TR_FromTPMPublic(0x81000081)
        self.ectx.EvictControl(
            ESYS_TR.OWNER, phandle, 0x81000081, session1=ESYS_TR.PASSWORD
        )
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.TR_FromTPMPublic(0x81000081)
        self.assertEqual(e.exception.error, TPM2_RC.HANDLE)

    def test_GetCapability(self):
        more = True
        while more:
            more, capdata = self.ectx.GetCapability(
                TPM2_CAP.COMMANDS, TPM2_CC.FIRST, lib.TPM2_MAX_CAP_CC
            )
            for c in capdata.data.command:
                pass

    def test_TestParms(self):
        parms = TPMT_PUBLIC_PARMS(type=TPM2_ALG.RSA)
        parms.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG.NULL
        parms.parameters.rsaDetail.scheme.scheme = TPM2_ALG.NULL
        parms.parameters.rsaDetail.keyBits = 2048
        parms.parameters.rsaDetail.exponent = 0

        self.ectx.TestParms(parms)

        parms.parameters.rsaDetail.keyBits = 1234
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.TestParms(parms)
        self.assertEqual(e.exception.error, TPM2_RC.VALUE)
        self.assertEqual(e.exception.parameter, 1)

    def test_ReadClock(self):
        ctime = self.ectx.ReadClock()
        self.assertGreater(ctime.time, 0)
        self.assertGreater(ctime.clockInfo.clock, 0)

    def test_ClockSet(self):
        newtime = 0xFA1AFE1
        self.ectx.ClockSet(ESYS_TR.OWNER, newtime, session1=ESYS_TR.PASSWORD)
        ntime = self.ectx.ReadClock()
        self.assertGreaterEqual(ntime.clockInfo.clock, newtime)

        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.ClockSet(ESYS_TR.OWNER, 0, session1=ESYS_TR.PASSWORD)
        self.assertEqual(e.exception.error, TPM2_RC.VALUE)

    def test_ClockRateAdjust(self):
        self.ectx.ClockRateAdjust(
            ESYS_TR.OWNER, TPM2_CLOCK.COARSE_SLOWER, session1=ESYS_TR.PASSWORD
        )

    def test_NV_UndefineSpaceSpecial(self):
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

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub, authHandle=ESYS_TR.RH_PLATFORM)

        session = self.ectx.StartAuthSession(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            None,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        self.ectx.PolicyCommandCode(session, TPM2_CC.NV_UndefineSpaceSpecial)

        self.ectx.NV_UndefineSpaceSpecial(
            nvhandle, session1=session, session2=ESYS_TR.PASSWORD
        )

    def test_NV_ReadPublic(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        pubout, name = self.ectx.NV_ReadPublic(nvhandle)

        self.assertEqual(nvpub.getName().name, name.name)

    def test_NV_Increment(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | (TPM2_NT.COUNTER << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        self.ectx.NV_Increment(nvhandle, authHandle=ESYS_TR.RH_OWNER)

        data = self.ectx.NV_Read(nvhandle, 8, 0, authHandle=ESYS_TR.RH_OWNER)

        counter = int.from_bytes(data.buffer, byteorder="big")
        self.assertEqual(counter, 1)

    def test_NV_Extend(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | (TPM2_NT.EXTEND << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=32,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        edata = b"\xFF" * 32
        self.ectx.NV_Extend(nvhandle, edata, authHandle=ESYS_TR.RH_OWNER)

        data = self.ectx.NV_Read(nvhandle, 32, 0, authHandle=ESYS_TR.RH_OWNER)

        edigest = b"\xbb\xa9\x1c\xa8]\xc9\x14\xb2\xec>\xfb\x9e\x16\xe7&{\xf9\x19;\x145\r \xfb\xa8\xa8\xb4\x06s\n\xe3\n"
        self.assertEqual(edigest, bytes(data))

    def test_NV_SetBits(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | (TPM2_NT.BITS << TPMA_NV.TPM2_NT_SHIFT),
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        bits = 0b1010
        self.ectx.NV_SetBits(nvhandle, bits, authHandle=ESYS_TR.RH_OWNER)

        data = self.ectx.NV_Read(nvhandle, 8, 0, authHandle=ESYS_TR.RH_OWNER)

        b = bits.to_bytes(length=8, byteorder="big")
        self.assertEqual(b, bytes(data))

    def test_NV_WriteLock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.WRITE_STCLEAR,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        self.ectx.NV_WriteLock(nvhandle, authHandle=ESYS_TR.RH_OWNER)

        indata = b"12345678"
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.NV_Write(nvhandle, indata, authHandle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

    def test_NV_GlobalWriteLock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD | TPMA_NV.GLOBALLOCK,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        self.ectx.NV_GlobalWriteLock()

        indata = b"12345678"
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.NV_Write(nvhandle, indata, authHandle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

    def test_NV_ReadLock(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE
                | TPMA_NV.OWNERREAD
                | TPMA_NV.READ_STCLEAR,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)

        indata = b"12345678"
        self.ectx.NV_Write(nvhandle, indata, authHandle=ESYS_TR.RH_OWNER)

        self.ectx.NV_ReadLock(nvhandle, authHandle=ESYS_TR.RH_OWNER)
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.NV_Read(nvhandle, 8, authHandle=ESYS_TR.RH_OWNER)

        self.assertEqual(e.exception.error, TPM2_RC.NV_LOCKED)

    def test_NV_ChangeAuth(self):
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

        nvhandle = self.ectx.NV_DefineSpace(b"first", nvpub)
        self.ectx.NV_Write(nvhandle, b"sometest", authHandle=ESYS_TR.RH_OWNER)

        self.ectx.NV_Read(nvhandle, 8, authHandle=nvhandle)

        session = self.ectx.StartAuthSession(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            None,
            TPM2_SE.POLICY,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )

        self.ectx.PolicyCommandCode(session, TPM2_CC.NV_ChangeAuth)

        self.ectx.NV_ChangeAuth(nvhandle, b"second", session1=session)

        self.ectx.NV_Read(nvhandle, 8, authHandle=nvhandle)

    def test_NV_Certify(self):
        nvpub = TPM2B_NV_PUBLIC(
            nvPublic=TPMS_NV_PUBLIC(
                nvIndex=0x1000000,
                nameAlg=TPM2_ALG.SHA256,
                attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD,
                authPolicy=b"",
                dataSize=8,
            )
        )

        nvhandle = self.ectx.NV_DefineSpace(b"", nvpub)
        self.ectx.NV_Write(nvhandle, b"sometest", authHandle=ESYS_TR.RH_OWNER)

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

        eccHandle, signPub, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        qualifyingData = TPM2B_DATA(b"qdata")
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)

        certifyInfo, _ = self.ectx.NV_Certify(
            eccHandle,
            nvhandle,
            qualifyingData,
            inScheme,
            8,
            authHandle=ESYS_TR.RH_OWNER,
            session1=ESYS_TR.PASSWORD,
            session2=ESYS_TR.PASSWORD,
        )
        att, _ = TPMS_ATTEST.Unmarshal(bytes(certifyInfo))
        self.assertEqual(att.magic, TPM2_GENERATED_VALUE(0xFF544347))
        self.assertEqual(att.type, TPM2_ST.ATTEST_NV)
        self.assertEqual(bytes(att.extraData), b"qdata")
        nvpub.nvPublic.attributes = nvpub.nvPublic.attributes | TPMA_NV.WRITTEN
        self.assertEqual(bytes(att.attested.nv.indexName), bytes(nvpub.getName()))
        self.assertEqual(att.attested.nv.offset, 0)
        self.assertEqual(att.attested.nv.nvContents.buffer, b"sometest")

    def test_Certify(self):
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

        eccHandle = self.ectx.CreatePrimary(inSensitive, inPublic)[0]

        qualifyingData = TPM2B_DATA()
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        certifyInfo, signature = self.ectx.Certify(
            eccHandle, eccHandle, qualifyingData, inScheme
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        certifyInfo, signature = self.ectx.Certify(
            eccHandle, eccHandle, b"12345678", inScheme
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.Certify(
                TPM2B_ATTEST(), eccHandle, qualifyingData, inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.Certify(
                eccHandle, 2.0, qualifyingData, inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.Certify(
                eccHandle, eccHandle, TPM2B_PUBLIC(), inScheme
            )

        with self.assertRaises(TypeError):
            certifyInfo, signature = self.ectx.Certify(
                eccHandle, eccHandle, qualifyingData, TPM2B_PRIVATE()
            )

        with self.assertRaises(TypeError):
            self.ectx.Certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session1=56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.Certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session2="foo"
            )

        with self.assertRaises(TypeError):
            self.ectx.Certify(
                eccHandle, eccHandle, qualifyingData, inScheme, session3=object()
            )

    def test_CertifyCreation(self):
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

        eccHandle, _, _, creationHash, creationTicket = self.ectx.CreatePrimary(
            inSensitive, inPublic
        )

        qualifyingData = TPM2B_DATA()
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        certifyInfo, signature = self.ectx.CertifyCreation(
            eccHandle, eccHandle, qualifyingData, creationHash, inScheme, creationTicket
        )
        self.assertEqual(type(certifyInfo), TPM2B_ATTEST)
        self.assertNotEqual(len(certifyInfo), 0)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                45.6, eccHandle, qualifyingData, creationHash, inScheme, creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle,
                object(),
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle,
                eccHandle,
                TPM2B_PUBLIC(),
                creationHash,
                inScheme,
                creationTicket,
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle, eccHandle, qualifyingData, object(), inScheme, creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle, eccHandle, qualifyingData, creationHash, [], creationTicket
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle, eccHandle, qualifyingData, creationHash, inScheme, 56.7
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session1=56.7,
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session2=object(),
            )

        with self.assertRaises(TypeError):
            self.ectx.CertifyCreation(
                eccHandle,
                eccHandle,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                session3="baz",
            )

    def test_Vendor_TCG_Test(self):
        with self.assertRaises(TSS2_Exception):
            self.ectx.Vendor_TCG_Test(b"random data")

        in_cdata = TPM2B_DATA(b"other bytes")._cdata
        with self.assertRaises(TSS2_Exception):
            self.ectx.Vendor_TCG_Test(in_cdata)

        with self.assertRaises(TypeError):
            self.ectx.Vendor_TCG_Test(None)

        with self.assertRaises(TypeError):
            self.ectx.Vendor_TCG_Test(TPM2B_PUBLIC())

    def test_FieldUpgradeStart(self):
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

        keyhandle, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.FieldUpgradeStart(
                ESYS_TR.PLATFORM,
                keyhandle,
                b"",
                TPMT_SIGNATURE(sigAlg=TPM2_ALG.NULL),
                session1=ESYS_TR.PASSWORD,
            )
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_FieldUpgradeData(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.FieldUpgradeData(b"")
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_FirmwareRead(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.FirmwareRead(0)
        self.assertEqual(e.exception.error, TPM2_RC.COMMAND_CODE)

    def test_shutdown_no_arg(self):
        self.ectx.Shutdown(TPM2_SU.STATE)

    def test_shutdown_state(self):
        self.ectx.Shutdown(TPM2_SU.STATE)

    def test_shutdown_clear(self):
        self.ectx.Shutdown(TPM2_SU.CLEAR)

    def test_shutdown_bad(self):
        with self.assertRaises(TypeError):
            self.ectx.Shutdown(object())

        with self.assertRaises(ValueError):
            self.ectx.Shutdown(42)

        with self.assertRaises(TypeError):
            self.ectx.Shutdown(session1=object())

        with self.assertRaises(TypeError):
            self.ectx.Shutdown(session2=object())

        with self.assertRaises(TypeError):
            self.ectx.Shutdown(session3=object())

    def test_policyrestart(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyRestart(session)

        with self.assertRaises(TypeError):
            self.ectx.PolicyRestart(object())

        with self.assertRaises(TypeError):
            self.ectx.PolicyRestart(session, session1=4.5)

        with self.assertRaises(TypeError):
            self.ectx.PolicyRestart(session, session2=object())

        with self.assertRaises(TypeError):
            self.ectx.PolicyRestart(session, session3=33.666)

    def test_duplicate(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.PolicyGetDigest(session)
        self.ectx.FlushContext(session)
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

        primary1, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic,)

        primary2, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

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

        priv, pub, _, _, _ = self.ectx.Create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.Load(primary1, priv, pub)

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)

        encryptionKey = TPM2B_DATA("is sixteen bytes")

        sym = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        encryptionKeyOut, duplicate, symSeed = self.ectx.Duplicate(
            childHandle, primary2, encryptionKey, sym, session1=session
        )
        self.assertEqual(type(encryptionKeyOut), TPM2B_DATA)
        self.assertEqual(type(duplicate), TPM2B_PRIVATE)
        self.assertEqual(type(symSeed), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(6.7, primary2, encryptionKey, sym, session1=session)

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle, object(), encryptionKey, sym, session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle, primary2, TPM2B_PUBLIC(), sym, session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle, primary2, encryptionKey, b"1234", session1=session
            )

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle, primary2, encryptionKey, sym, session1=7.89
            )

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle,
                primary2,
                encryptionKey,
                sym,
                session1=session,
                session2="foo",
            )

        with self.assertRaises(TypeError):
            self.ectx.Duplicate(
                childHandle,
                primary2,
                encryptionKey,
                sym,
                session1=session,
                session2=ESYS_TR.PASSWORD,
                session3="foo",
            )

    def test_PolicyAuthValue(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)

        with self.assertRaises(TypeError):
            self.ectx.PolicyAuthValue(b"1234")

    def test_PolicyCommandCode(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)

        with self.assertRaises(TypeError):
            self.ectx.PolicyCommandCode(b"1234", TPM2_CC.Duplicate)

        with self.assertRaises(TypeError):
            self.ectx.PolicyCommandCode(session, b"12345")

        with self.assertRaises(ValueError):
            self.ectx.PolicyCommandCode(session, 42)

    def test_PolicyGetDigest(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.PolicyGetDigest(session)
        self.assertTrue(type(policyDigest), TPM2B_DIGEST)

    def test_rewrap(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.PolicyGetDigest(session)
        self.ectx.FlushContext(session)
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

        primary1, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        primary2, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

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

        priv, pub, _, _, _ = self.ectx.Create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.Load(primary1, priv, pub)

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)

        encryptionKey = TPM2B_DATA("is sixteen bytes")

        sym = TPMT_SYM_DEF_OBJECT(
            algorithm=TPM2_ALG.AES,
            keyBits=TPMU_SYM_KEY_BITS(aes=128),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        _, duplicate, symSeed = self.ectx.Duplicate(
            childHandle, primary2, encryptionKey, sym, session1=session
        )

        keyName = pub.publicArea.getName()
        duplicate, symSeed = self.ectx.Rewrap(
            primary2, primary1, duplicate, keyName, symSeed
        )
        self.assertEqual(type(duplicate), TPM2B_PRIVATE)
        self.assertEqual(type(symSeed), TPM2B_ENCRYPTED_SECRET)

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(67.3, primary1, duplicate, keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(primary2, object(), duplicate, keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(primary2, primary1, TPM2B_NAME(), keyName, symSeed)

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(primary2, primary1, duplicate, TPM2B_PRIVATE(), symSeed)

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(
                primary2, primary1, duplicate, keyName, symSeed, session1="goo"
            )

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(
                primary2, primary1, duplicate, keyName, symSeed, session2=45.6
            )

        with self.assertRaises(TypeError):
            self.ectx.Rewrap(
                primary2, primary1, duplicate, keyName, symSeed, sesion3=object()
            )

    def test_Import(self):

        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.TRIAL,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)
        policyDigest = self.ectx.PolicyGetDigest(session)
        self.ectx.FlushContext(session)
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

        primary1, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

        primary2, _, _, _, _ = self.ectx.CreatePrimary(inSensitive, inPublic)

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

        priv, pub, _, _, _ = self.ectx.Create(primary1, inSensitive, inPublic)

        childHandle = self.ectx.Load(primary1, priv, pub)

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.POLICY,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.PolicyAuthValue(session)
        self.ectx.PolicyCommandCode(session, TPM2_CC.Duplicate)

        sym = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL,)

        encryptionKey, duplicate, symSeed = self.ectx.Duplicate(
            childHandle, primary2, None, sym, session1=session
        )

        private = self.ectx.Import(
            primary1, encryptionKey, pub, duplicate, symSeed, sym
        )

        self.assertEqual(type(private), TPM2B_PRIVATE)

        with self.assertRaises(TypeError):
            self.ectx.Import(98.5, encryptionKey, pub, duplicate, symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.Import(primary1, TPM2B_ECC_POINT(), pub, duplicate, symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.Import(
                primary1, encryptionKey, TPM2B_DATA(), duplicate, symSeed, sym
            )

        with self.assertRaises(TypeError):
            self.ectx.Import(primary1, encryptionKey, pub, object(), symSeed, sym)

        with self.assertRaises(TypeError):
            self.ectx.Import(primary1, encryptionKey, pub, duplicate, None, sym)

        with self.assertRaises(TypeError):
            self.ectx.Import(
                primary1, encryptionKey, pub, duplicate, symSeed, TPM2B_PUBLIC()
            )

        with self.assertRaises(TypeError):
            self.ectx.Import(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session1="boo"
            )

        with self.assertRaises(TypeError):
            self.ectx.Import(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.Import(
                primary1, encryptionKey, pub, duplicate, symSeed, sym, session3=4.5
            )

    def test_Quote(self):

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

        parentHandle = self.ectx.CreatePrimary(inSensitive, inPublic)[0]

        quote, signature = self.ectx.Quote(
            parentHandle, "sha256:1,2,3,4", TPM2B_DATA(b"123456789")
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        quote, signature = self.ectx.Quote(
            parentHandle, TPML_PCR_SELECTION.parse("sha256:1,2,3,4"), TPM2B_DATA()
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        quote, signature = self.ectx.Quote(
            parentHandle,
            "sha256:1,2,3,4",
            TPM2B_DATA(),
            inScheme=TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
        )
        self.assertTrue(type(quote), TPM2B_ATTEST)
        self.assertTrue(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.Quote(42.0, "sha256:1,2,3,4", TPM2B_DATA())

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, b"sha256:1,2,3,4")

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, "sha256:1,2,3,4", qualifyingData=object())

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, "sha256:1,2,3,4", inScheme=87)

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, "sha256:1,2,3,4", session1="foo")

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, "sha256:1,2,3,4", session2=25.68)

        with self.assertRaises(TypeError):
            self.ectx.Quote(parentHandle, "sha256:1,2,3,4", session3=object())

    def test_GetSessionAuditDigest(self):

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

        signHandle = self.ectx.CreatePrimary(inSensitive, inPublic)[0]

        sym = TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL,)

        session = self.ectx.StartAuthSession(
            tpmKey=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            nonceCaller=None,
            sessionType=TPM2_SE.HMAC,
            symmetric=sym,
            authHash=TPM2_ALG.SHA256,
        )

        self.ectx.TRSess_SetAttributes(
            session, TPMA_SESSION.AUDIT | TPMA_SESSION.CONTINUESESSION
        )

        self.ectx.GetCapability(
            TPM2_CAP.COMMANDS, TPM2_CC.FIRST, lib.TPM2_MAX_CAP_CC, session1=session
        )

        auditInfo, signature = self.ectx.GetSessionAuditDigest(
            signHandle, session, b"1234"
        )
        self.assertEqual(type(auditInfo), TPM2B_ATTEST)
        self.assertEqual(type(signature), TPMT_SIGNATURE)

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(45.89, session, b"1234")

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(signHandle, object(), b"1234")

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(signHandle, session, list())

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(
                signHandle, session, b"1234", privacyAdminHandle=45.6
            )

        with self.assertRaises(ValueError):
            self.ectx.GetSessionAuditDigest(
                signHandle, session, b"1234", privacyAdminHandle=ESYS_TR.LOCKOUT
            )

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(
                signHandle, session, b"1234", session1="baz"
            )

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(
                signHandle, session, b"1234", session2=object()
            )

        with self.assertRaises(TypeError):
            self.ectx.GetSessionAuditDigest(
                signHandle, session, b"1234", session3=12.723
            )

    def test_PP_Commands(self):
        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.PP_Commands(TPML_CC(), TPML_CC(), session1=ESYS_TR.PASSWORD)
        self.assertEqual(e.exception.error, TPM2_RC.PP)
        self.assertEqual(e.exception.session, 1)

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(b"bad setList", TPML_CC(), session1=ESYS_TR.PASSWORD)

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(TPML_CC(), None, session1=ESYS_TR.PASSWORD)

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(TPML_CC(), TPML_CC(), session1=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(TPML_CC(), TPML_CC(), session2=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(TPML_CC(), TPML_CC(), session3=b"0xF1F1")

        with self.assertRaises(TypeError):
            self.ectx.PP_Commands(TPML_CC(), TPML_CC(), authHandle="platform")

    def test_SetAlgorithmSet(self):
        self.ectx.SetAlgorithmSet(0)

        with self.assertRaises(TypeError):
            self.ectx.SetAlgorithmSet([1, 2, 3])

        with self.assertRaises(TypeError):
            self.ectx.SetAlgorithmSet(session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.SetAlgorithmSet(session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.SetAlgorithmSet(session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.SetAlgorithmSet(authHandle=None)

    def test_DictionaryAttackLockReset(self):
        self.ectx.DictionaryAttackLockReset()

        with self.assertRaises(TSS2_Exception) as e:
            self.ectx.DictionaryAttackLockReset(lockHandle=ESYS_TR.RH_OWNER)
        self.assertEqual(e.exception.error, 132)
        self.assertEqual(e.exception.handle, 1)

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackLockReset([1, 2, 3])

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackLockReset(session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackLockReset(session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackLockReset(session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackLockReset(lockHandle=None)

    def test_DictionaryAttackParameters(self):
        self.ectx.DictionaryAttackParameters(1, 2, 3)

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(None, 2, 3)

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, None, 3)

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, 2, None)

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, 2, 3, session2=set(3, 2, 1))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, 2, 3, session1=set(4, 3, 2))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, 2, 3, session3=set(5, 4, 3))

        with self.assertRaises(TypeError):
            self.ectx.DictionaryAttackParameters(1, 2, 3, lockHandle=None)


if __name__ == "__main__":
    unittest.main()
