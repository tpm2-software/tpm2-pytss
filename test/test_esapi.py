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


        x, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER,
            inSensitive,
            inPublic,
            outsideInfo,
            creationPCR,
            session1=ESYS_TR.PASSWORD,
        )
        self.assertIsNot(x, None)

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
        nv_index = self.ectx.NV_DefineSpace(ESYS_TR.OWNER, None, nv_public)
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

        self.ectx.NV_UndefineSpace(ESYS_TR.OWNER, nv_index)

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

    def test_incremental_resume_test(self):
        algs = TPML_ALG.parse("rsa,ecc,xor,aes,cbc")

        self.ectx.IncrementalSelfTest(algs)
        toDo, rc = self.ectx.GetTestResult()
        self.assertTrue(
            isinstance(toDo, TPM2B_MAX_BUFFER),
            f"Expected TODO list to be TPM2B_MAX_BUFFER, got: {type(toDo)}",
        )
        self.assertEqual(rc, TPM2_RC.SUCCESS)

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

    def test_start_authSession_enckey(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE()
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

    def test_start_authSession_noncecaller(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        alg = "rsa2048"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )

        self.assertTrue(
            isinstance(priv, TPM2B_PRIVATE),
            f"Expected TPM2B_PRIVATE, got: {type(priv)}",
        )
        self.assertTrue(
            isinstance(pub, TPM2B_PUBLIC), f"Expected TPM2B_PUBLIC, got: {type(pub)}"
        )

    def test_load(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        alg = "rsa2048"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)
        self.assertTrue(childHandle)

    def test_readpublic(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        childInSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("childpassword"))
        )

        alg = "rsa2048"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        childInPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))

        priv, pub, _, _, _ = self.ectx.Create(
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )

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

    def test_makecredential(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
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

    def test_unseal(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
        )

        childHandle = self.ectx.Load(parentHandle, priv, pub)

        self.ectx.setAuth(childHandle, "childpassword")

        secret = self.ectx.Unseal(childHandle)
        self.assertEqual(bytes(secret), b"sealedsecret")

    def test_objectChangeAuth(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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
            parentHandle, childInSensitive, childInPublic, outsideInfo, creationPCR
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

    def test_createloaded(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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
        self.assertNotEqual(priv, None)
        self.assertNotEqual(pub, None)

    def test_rsa_enc_dec(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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

    def test_rsa_enc_dec_with_label(self):

        alg = "rsa2048:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH("password"))
        )
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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

        alg = "ecc256:aes128cfb"
        attrs = TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
        inPublic = TPM2B_PUBLIC(TPMT_PUBLIC.parse(alg=alg, objectAttributes=attrs))
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        zPoint, pubPoint = self.ectx.ECDH_KeyGen(parentHandle)
        self.assertNotEqual(zPoint, None)
        self.assertNotEqual(pubPoint, None)

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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
        self.assertNotEqual(outPoint, None)

    def test_ECC_Parameters(self):

        params = self.ectx.ECC_Parameters(TPM2_ECC_CURVE.NIST_P256)
        self.assertNotEqual(params, None)

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        eccHandle, outPublic, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        curveId = TPM2_ECC.NIST_P256

        Q, counter = self.ectx.EC_Ephemeral(curveId)

        inQsB = TPM2B_ECC_POINT(outPublic.publicArea.unique.ecc)
        inQeB = Q
        Z1, Z2 = self.ectx.ZGen_2Phase(eccHandle, inQsB, inQeB, TPM2_ALG.ECDH, counter)
        self.assertNotEqual(Z1, None)
        self.assertNotEqual(Z2, None)

    def test_EncryptDecrypt(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="ecc",
                objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

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

    def test_EncryptDecrypt2(self):

        inPublic = TPM2B_PUBLIC(
            TPMT_PUBLIC.parse(
                alg="ecc",
                objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS,
            )
        )
        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

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

    def test_HMAC(self):

        attrs = (
            TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
        )
        templ = TPMT_PUBLIC.parse(alg="hmac", objectAttributes=attrs)
        inPublic = TPM2B_PUBLIC(templ)

        inSensitive = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        primaryHandle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

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

    def test_StirRandom(self):

        self.ectx.StirRandom(b"1234")
        self.ectx.StirRandom("1234")
        self.ectx.StirRandom(TPM2B_SENSITIVE_DATA("1234"))

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, outpub, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        handle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_PLATFORM, b"", nvpub)

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
            nvhandle, ESYS_TR.RH_PLATFORM, session1=session, session2=ESYS_TR.PASSWORD
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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        self.ectx.NV_Increment(ESYS_TR.RH_OWNER, nvhandle, session1=ESYS_TR.PASSWORD)

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        edata = b"\xFF" * 32
        self.ectx.NV_Extend(
            ESYS_TR.RH_OWNER, nvhandle, edata, session1=ESYS_TR.PASSWORD
        )

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        bits = 0b1010
        self.ectx.NV_SetBits(
            ESYS_TR.RH_OWNER, nvhandle, bits, session1=ESYS_TR.PASSWORD
        )

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        self.ectx.NV_WriteLock(ESYS_TR.RH_OWNER, nvhandle, session1=ESYS_TR.PASSWORD)

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        self.ectx.NV_GlobalWriteLock(ESYS_TR.RH_OWNER, session1=ESYS_TR.PASSWORD)

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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)

        indata = b"12345678"
        self.ectx.NV_Write(nvhandle, indata, authHandle=ESYS_TR.RH_OWNER)

        self.ectx.NV_ReadLock(ESYS_TR.RH_OWNER, nvhandle, session1=ESYS_TR.PASSWORD)
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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"first", nvpub)
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

        nvhandle = self.ectx.NV_DefineSpace(ESYS_TR.RH_OWNER, b"", nvpub)
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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        eccHandle, signPub, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        qualifyingData = TPM2B_DATA(b"qdata")
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)

        certifyInfo, signature = self.ectx.NV_Certify(
            eccHandle,
            ESYS_TR.RH_OWNER,
            nvhandle,
            qualifyingData,
            inScheme,
            8,
            0,
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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        eccHandle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

        qualifyingData = TPM2B_DATA()
        inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
        certifyInfo, signature = self.ectx.Certify(
            eccHandle, eccHandle, qualifyingData, inScheme
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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        eccHandle, _, _, creationHash, creationTicket = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        keyhandle, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        primary1, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        primary2, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        priv, pub, _, _, _ = self.ectx.Create(
            primary1, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        primary1, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        primary2, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        priv, pub, _, _, _ = self.ectx.Create(
            primary1, inSensitive, inPublic, outsideInfo, creationPCR
        )

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
            self.ectx.Rewrap(primary2, primary1, duplicate, keyName, TPMT_PUBLIC())

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

        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        primary1, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

        primary2, _, _, _, _ = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )

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

        priv, pub, _, _, _ = self.ectx.Create(
            primary1, inSensitive, inPublic, outsideInfo, creationPCR
        )

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
        outsideInfo = TPM2B_DATA()
        creationPCR = TPML_PCR_SELECTION()

        parentHandle = self.ectx.CreatePrimary(
            ESYS_TR.OWNER, inSensitive, inPublic, outsideInfo, creationPCR
        )[0]

        quote, signature = self.ectx.Quote(parentHandle, "sha256:1,2,3,4", TPM2B_DATA(b'123456789'))
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


if __name__ == "__main__":
    unittest.main()
