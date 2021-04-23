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

        self.ectx.setAuth(ESYS_TR.OWNER, "")

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


if __name__ == "__main__":
    unittest.main()
