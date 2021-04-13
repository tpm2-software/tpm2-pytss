#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-3
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
        self.assertEqual(value, b"hello world")

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


if __name__ == "__main__":
    unittest.main()
