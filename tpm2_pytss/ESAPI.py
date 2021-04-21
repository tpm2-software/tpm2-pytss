"""
SPDX-License-Identifier: BSD-2
"""

from ._libtpm2_pytss import lib

from .types import *

from .utils import _chkrc, TPM2B_pack, TPM2B_unpack


class ESAPI:
    def __init__(self, tcti=None):

        tctx = ffi.NULL if tcti is None else tcti.ctx

        self.ctx_pp = ffi.new("ESYS_CONTEXT **")
        _chkrc(lib.Esys_Initialize(self.ctx_pp, tctx, ffi.NULL))
        self.ctx = self.ctx_pp[0]

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        lib.Esys_Finalize(self.ctx_pp)
        self.ctx = ffi.NULL

    def setAuth(self, esys_tr, auth):

        auth_p = TPM2B_pack(auth, "TPM2B_AUTH")
        _chkrc(lib.Esys_TR_SetAuth(self.ctx, esys_tr, auth_p))

    def TR_GetName(self, handle):
        name = ffi.new("TPM2B_NAME **")
        _chkrc(lib.Esys_TR_GetName(self.ctx, handle, name))
        return TPM2B_NAME(_cdata=name[0])

    def Startup(self, startupType):
        _chkrc(lib.Esys_Startup(self.ctx, startupType))

    def Shutdown(
        self,
        shutdownType,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_Shutdown(self.ctx, session1, session2, session3, shutdownType))

    def SelfTest(
        self,
        fullTest,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_SelfTest(self.ctx, session1, session2, session3, fullTest))

    def IncrementalSelfTest(
        self,
        toTest,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        toDoList = ffi.new("TPML_ALG **")
        _chkrc(
            lib.Esys_IncrementalSelfTest(
                self.ctx, session1, session2, session3, toTest._cdata, toDoList
            )
        )
        return TPML_ALG(toDoList[0])

    def GetTestResult(
        self, session1=ESYS_TR.NONE, session2=ESYS_TR.NONE, session3=ESYS_TR.NONE
    ):

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        testResult = ffi.new("TPM2_RC *")
        _chkrc(
            lib.Esys_GetTestResult(
                self.ctx, session1, session2, session3, outData, testResult
            )
        )
        return (TPM2B_MAX_BUFFER(outData[0]), TPM2_RC(testResult[0]))

    def StartAuthSession(
        self,
        tpmKey,
        bind,
        nonceCaller,
        sessionType,
        symmetric,
        authHash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if nonceCaller is None:
            nonceCaller = ffi.NULL
        elif isinstance(nonceCaller, TPM_OBJECT):
            nonceCaller = nonceCaller._cdata
        else:
            raise TypeError("Expected nonceCaller to be None or TPM_OBJECT")

        sessionHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_StartAuthSession(
                self.ctx,
                tpmKey,
                bind,
                session1,
                session2,
                session3,
                nonceCaller,
                sessionType,
                symmetric._cdata,
                authHash,
                sessionHandle,
            )
        )
        sessionHandleObject = sessionHandle[0]
        return sessionHandleObject

    def TRSess_SetAttributes(self, session, attributes, mask=0xFF):

        _chkrc(lib.Esys_TRSess_SetAttributes(self.ctx, session, attributes, mask))

    def PolicyRestart(
        self,
        sessionHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyRestart(
                self.ctx, sessionHandle, session1, session2, session3
            )
        )

    def Create(
        self,
        parentHandle,
        inSensitive,
        inPublic,
        outsideInfo,
        creationPCR,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_Create(
                self.ctx,
                parentHandle,
                session1,
                session2,
                session3,
                inSensitive._cdata,
                inPublic._cdata,
                outsideInfo._cdata,
                creationPCR._cdata,
                outPrivate,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )
        return (
            TPM2B_PRIVATE(outPrivate[0]),
            TPM2B_PUBLIC(outPublic[0]),
            TPM2B_CREATION_DATA(creationData[0]),
            TPM2B_DIGEST(creationHash[0]),
            TPMT_TK_CREATION(creationTicket[0]),
        )

    def Load(
        self,
        parentHandle,
        inPrivate,
        inPublic,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_Load(
                self.ctx,
                parentHandle,
                session1,
                session2,
                session3,
                inPrivate._cdata,
                inPublic._cdata,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def LoadExternal(
        self,
        inPrivate,
        inPublic,
        hierarchy,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_LoadExternal(
                self.ctx,
                session1,
                session2,
                session3,
                inPrivate._cdata,
                inPublic._cdata,
                hierarchy,
                objectHandle,
            )
        )
        objectHandleObject = objectHandle[0]
        return objectHandleObject

    def ReadPublic(
        self,
        objectHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outPublic = ffi.new("TPM2B_PUBLIC **")
        name = ffi.new("TPM2B_NAME **")
        qualifiedName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_ReadPublic(
                self.ctx,
                objectHandle,
                session1,
                session2,
                session3,
                outPublic,
                name,
                qualifiedName,
            )
        )
        return (
            TPM2B_PUBLIC(outPublic[0]),
            TPM2B_NAME(name[0]),
            TPM2B_NAME(qualifiedName[0]),
        )

    def ActivateCredential(
        self,
        activateHandle,
        keyHandle,
        credentialBlob,
        secret,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        certInfo = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_ActivateCredential(
                self.ctx,
                activateHandle,
                keyHandle,
                session1,
                session2,
                session3,
                credentialBlob._cdata,
                secret._cdata,
                certInfo,
            )
        )
        return TPM2B_DIGEST(certInfo[0])

    def MakeCredential(
        self,
        handle,
        credential,
        objectName,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        credentialBlob = ffi.new("TPM2B_ID_OBJECT **")
        secret = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_MakeCredential(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                credential._cdata,
                objectName._cdata,
                credentialBlob,
                secret,
            )
        )
        return (TPM2B_ID_OBJECT(credentialBlob[0]), TPM2B_ENCRYPTED_SECRET(secret[0]))

    def Unseal(
        self,
        itemHandle,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outData = ffi.new("TPM2B_SENSITIVE_DATA **")
        _chkrc(
            lib.Esys_Unseal(self.ctx, itemHandle, session1, session2, session3, outData)
        )
        return TPM2B_SENSITIVE_DATA(outData[0])

    def ObjectChangeAuth(
        self,
        objectHandle,
        parentHandle,
        newAuth,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        if isinstance(newAuth, (str, bytes)):
            newAuth = TPM2B_AUTH(newAuth)

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_ObjectChangeAuth(
                self.ctx,
                objectHandle,
                parentHandle,
                session1,
                session2,
                session3,
                newAuth._cdata,
                outPrivate,
            )
        )
        return TPM2B_PRIVATE(outPrivate[0])

    def CreateLoaded(
        self,
        parentHandle,
        inSensitive,
        inPublic,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        objectHandle = ffi.new("ESYS_TR *")
        outPrivate = ffi.new("TPM2B_PRIVATE **")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        _chkrc(
            lib.Esys_CreateLoaded(
                self.ctx,
                parentHandle,
                session1,
                session2,
                session3,
                inSensitive._cdata,
                inPublic._cdata,
                objectHandle,
                outPrivate,
                outPublic,
            )
        )
        objectHandleObject = objectHandle[0]
        return (
            objectHandleObject,
            TPM2B_PRIVATE(outPrivate[0]),
            TPM2B_PUBLIC(outPublic[0]),
        )

    def Duplicate(
        self,
        objectHandle,
        newParentHandle,
        encryptionKeyIn,
        symmetricAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        encryptionKeyOut = ffi.new("TPM2B_DATA **")
        duplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Duplicate(
                self.ctx,
                objectHandle,
                newParentHandle,
                session1,
                session2,
                session3,
                encryptionKeyIn,
                symmetricAlg,
                encryptionKeyOut,
                duplicate,
                outSymSeed,
            )
        )
        return (encryptionKeyOut[0], duplicate[0], outSymSeed[0])

    def Rewrap(
        self,
        oldParent,
        newParent,
        inDuplicate,
        name,
        inSymSeed,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outDuplicate = ffi.new("TPM2B_PRIVATE **")
        outSymSeed = ffi.new("TPM2B_ENCRYPTED_SECRET **")
        _chkrc(
            lib.Esys_Rewrap(
                self.ctx,
                oldParent,
                newParent,
                session1,
                session2,
                session3,
                inDuplicate,
                name,
                inSymSeed,
                outDuplicate,
                outSymSeed,
            )
        )
        return (outDuplicate[0], outSymSeed[0])

    def Import(
        self,
        parentHandle,
        encryptionKey,
        objectPublic,
        duplicate,
        inSymSeed,
        symmetricAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outPrivate = ffi.new("TPM2B_PRIVATE **")
        _chkrc(
            lib.Esys_Import(
                self.ctx,
                parentHandle,
                session1,
                session2,
                session3,
                encryptionKey,
                objectPublic,
                duplicate,
                inSymSeed,
                symmetricAlg,
                outPrivate,
            )
        )
        return outPrivate[0]

    def RSA_Encrypt(
        self,
        keyHandle,
        message,
        inScheme,
        label=None,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if label is None:
            label = TPM2B_DATA()

        outData = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Encrypt(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                message._cdata,
                inScheme._cdata,
                label._cdata,
                outData,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(outData[0])

    def RSA_Decrypt(
        self,
        keyHandle,
        cipherText,
        inScheme,
        label=None,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if label is None:
            label = TPM2B_DATA()

        message = ffi.new("TPM2B_PUBLIC_KEY_RSA **")
        _chkrc(
            lib.Esys_RSA_Decrypt(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                cipherText._cdata,
                inScheme._cdata,
                label._cdata,
                message,
            )
        )
        return TPM2B_PUBLIC_KEY_RSA(message[0])

    def ECDH_KeyGen(
        self,
        keyHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        zPoint = ffi.new("TPM2B_ECC_POINT **")
        pubPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_KeyGen(
                self.ctx, keyHandle, session1, session2, session3, zPoint, pubPoint
            )
        )
        return (TPM2B_ECC_POINT(zPoint[0]), TPM2B_ECC_POINT(pubPoint[0]))

    def ECDH_ZGen(
        self,
        keyHandle,
        inPoint,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outPoint = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ECDH_ZGen(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                inPoint._cdata,
                outPoint,
            )
        )
        return TPM2B_ECC_POINT(outPoint[0])

    def ECC_Parameters(
        self,
        curveID,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        parameters = ffi.new("TPMS_ALGORITHM_DETAIL_ECC **")
        _chkrc(
            lib.Esys_ECC_Parameters(
                self.ctx, session1, session2, session3, curveID, parameters
            )
        )
        return TPMS_ALGORITHM_DETAIL_ECC(parameters[0])

    def ZGen_2Phase(
        self,
        keyA,
        inQsB,
        inQeB,
        inScheme,
        counter,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outZ1 = ffi.new("TPM2B_ECC_POINT **")
        outZ2 = ffi.new("TPM2B_ECC_POINT **")
        _chkrc(
            lib.Esys_ZGen_2Phase(
                self.ctx,
                keyA,
                session1,
                session2,
                session3,
                inQsB,
                inQeB,
                inScheme,
                counter,
                outZ1,
                outZ2,
            )
        )
        return (outZ1[0], outZ2[0])

    def EncryptDecrypt(
        self,
        keyHandle,
        decrypt,
        mode,
        ivIn,
        inData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                decrypt,
                mode,
                ivIn,
                inData,
                outData,
                ivOut,
            )
        )
        return (outData[0], ivOut[0])

    def EncryptDecrypt2(
        self,
        keyHandle,
        inData,
        decrypt,
        mode,
        ivIn,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outData = ffi.new("TPM2B_MAX_BUFFER **")
        ivOut = ffi.new("TPM2B_IV **")
        _chkrc(
            lib.Esys_EncryptDecrypt2(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                inData,
                decrypt,
                mode,
                ivIn,
                outData,
                ivOut,
            )
        )
        return (outData[0], ivOut[0])

    def Hash(
        self,
        data,
        hashAlg,
        hierarchy,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outHash = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_Hash(
                self.ctx,
                session1,
                session2,
                session3,
                data,
                hashAlg,
                hierarchy,
                outHash,
                validation,
            )
        )
        return (outHash[0], validation[0])

    def HMAC(
        self,
        handle,
        buffer,
        hashAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outHMAC = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_HMAC(
                self.ctx, handle, session1, session2, session3, buffer, hashAlg, outHMAC
            )
        )
        return outHMAC[0]

    def GetRandom(
        self,
        bytesRequested,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        randomBytes = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_GetRandom(
                self.ctx, session1, session2, session3, bytesRequested, randomBytes
            )
        )

        return TPM2B_unpack(randomBytes[0])

    def StirRandom(
        self,
        inData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_StirRandom(self.ctx, session1, session2, session3, inData))

    def HMAC_Start(
        self,
        handle,
        auth,
        hashAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HMAC_Start(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                auth,
                hashAlg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def HashSequenceStart(
        self,
        auth,
        hashAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HashSequenceStart(
                self.ctx, session1, session2, session3, auth, hashAlg, sequenceHandle
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def SequenceUpdate(
        self,
        sequenceHandle,
        buffer,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_SequenceUpdate(
                self.ctx, sequenceHandle, session1, session2, session3, buffer
            )
        )

    def SequenceComplete(
        self,
        sequenceHandle,
        buffer,
        hierarchy,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        result = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_SequenceComplete(
                self.ctx,
                sequenceHandle,
                session1,
                session2,
                session3,
                buffer,
                hierarchy,
                result,
                validation,
            )
        )
        return (result[0], validation[0])

    def EventSequenceComplete(
        self,
        pcrHandle,
        sequenceHandle,
        buffer,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        results = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_EventSequenceComplete(
                self.ctx,
                pcrHandle,
                sequenceHandle,
                session1,
                session2,
                session3,
                buffer,
                results,
            )
        )
        return results[0]

    def Certify(
        self,
        objectHandle,
        signHandle,
        qualifyingData,
        inScheme,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Certify(
                self.ctx,
                objectHandle,
                signHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                certifyInfo,
                signature,
            )
        )
        return (certifyInfo[0], signature[0])

    def CertifyCreation(
        self,
        signHandle,
        objectHandle,
        qualifyingData,
        creationHash,
        inScheme,
        creationTicket,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_CertifyCreation(
                self.ctx,
                signHandle,
                objectHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                creationHash,
                inScheme,
                creationTicket,
                certifyInfo,
                signature,
            )
        )
        return (certifyInfo[0], signature[0])

    def Quote(
        self,
        signHandle,
        qualifyingData,
        inScheme,
        PCRselect,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        quoted = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Quote(
                self.ctx,
                signHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                PCRselect,
                quoted,
                signature,
            )
        )
        return (quoted[0], signature[0])

    def GetSessionAuditDigest(
        self,
        privacyAdminHandle,
        signHandle,
        sessionHandle,
        qualifyingData,
        inScheme,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetSessionAuditDigest(
                self.ctx,
                privacyAdminHandle,
                signHandle,
                sessionHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                auditInfo,
                signature,
            )
        )
        return (auditInfo[0], signature[0])

    def GetCommandAuditDigest(
        self,
        privacyHandle,
        signHandle,
        qualifyingData,
        inScheme,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        auditInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetCommandAuditDigest(
                self.ctx,
                privacyHandle,
                signHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                auditInfo,
                signature,
            )
        )
        return (auditInfo[0], signature[0])

    def GetTime(
        self,
        privacyAdminHandle,
        signHandle,
        qualifyingData,
        inScheme,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        timeInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_GetTime(
                self.ctx,
                privacyAdminHandle,
                signHandle,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                timeInfo,
                signature,
            )
        )
        return (timeInfo[0], signature[0])

    def Commit(
        self,
        signHandle,
        P1,
        s2,
        y2,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        K = ffi.new("TPM2B_ECC_POINT **")
        L = ffi.new("TPM2B_ECC_POINT **")
        E = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_Commit(
                self.ctx,
                signHandle,
                session1,
                session2,
                session3,
                P1,
                s2,
                y2,
                K,
                L,
                E,
                counter,
            )
        )
        return (K[0], L[0], E[0], counter[0])

    def EC_Ephemeral(
        self,
        curveID,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        Q = ffi.new("TPM2B_ECC_POINT **")
        counter = ffi.new("UINT16 *")
        _chkrc(
            lib.Esys_EC_Ephemeral(
                self.ctx, session1, session2, session3, curveID, Q, counter
            )
        )
        return (Q[0], counter[0])

    def VerifySignature(
        self,
        keyHandle,
        digest,
        signature,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        validation = ffi.new("TPMT_TK_VERIFIED **")
        _chkrc(
            lib.Esys_VerifySignature(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                digest,
                signature,
                validation,
            )
        )
        return validation[0]

    def Sign(
        self,
        keyHandle,
        digest,
        inScheme,
        validation,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_Sign(
                self.ctx,
                keyHandle,
                session1,
                session2,
                session3,
                digest,
                inScheme,
                validation,
                signature,
            )
        )
        return signature[0]

    def SetCommandCodeAuditStatus(
        self,
        auth,
        auditAlg,
        setList,
        clearList,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_SetCommandCodeAuditStatus(
                self.ctx,
                auth,
                session1,
                session2,
                session3,
                auditAlg,
                setList,
                clearList,
            )
        )

    def PCR_Extend(
        self,
        pcrHandle,
        digests,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PCR_Extend(
                self.ctx, pcrHandle, session1, session2, session3, digests
            )
        )

    def PCR_Event(
        self,
        pcrHandle,
        eventData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        digests = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_PCR_Event(
                self.ctx, pcrHandle, session1, session2, session3, eventData, digests
            )
        )
        return digests[0]

    def PCR_Read(
        self,
        pcrSelectionIn,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        pcrUpdateCounter = ffi.new("UINT32 *")
        pcrSelectionOut = ffi.new("TPML_PCR_SELECTION **")
        pcrValues = ffi.new("TPML_DIGEST **")
        _chkrc(
            lib.Esys_PCR_Read(
                self.ctx,
                session1,
                session2,
                session3,
                pcrSelectionIn._cdata,
                pcrUpdateCounter,
                pcrSelectionOut,
                pcrValues,
            )
        )

        return (
            pcrUpdateCounter[0],
            TPML_PCR_SELECTION(_cdata=pcrSelectionOut[0]),
            TPML_DIGEST(_cdata=pcrValues[0]),
        )

    def PCR_Allocate(
        self,
        authHandle,
        pcrAllocation,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        allocationSuccess = ffi.new("TPMI_YES_NO *")
        maxPCR = ffi.new("UINT32 *")
        sizeNeeded = ffi.new("UINT32 *")
        sizeAvailable = ffi.new("UINT32 *")
        _chkrc(
            lib.Esys_PCR_Allocate(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                pcrAllocation,
                allocationSuccess,
                maxPCR,
                sizeNeeded,
                sizeAvailable,
            )
        )
        return (allocationSuccess[0], maxPCR[0], sizeNeeded[0], sizeAvailable[0])

    def PCR_SetAuthPolicy(
        self,
        authHandle,
        authPolicy,
        hashAlg,
        pcrNum,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PCR_SetAuthPolicy(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                authPolicy,
                hashAlg,
                pcrNum,
            )
        )

    def PCR_SetAuthValue(
        self,
        pcrHandle,
        auth,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PCR_SetAuthValue(
                self.ctx, pcrHandle, session1, session2, session3, auth
            )
        )

    def PCR_Reset(
        self,
        pcrHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_PCR_Reset(self.ctx, pcrHandle, session1, session2, session3))

    def PolicySigned(
        self,
        authObject,
        policySession,
        nonceTPM,
        cpHashA,
        policyRef,
        expiration,
        auth,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySigned(
                self.ctx,
                authObject,
                policySession,
                session1,
                session2,
                session3,
                nonceTPM,
                cpHashA,
                policyRef,
                expiration,
                auth,
                timeout,
                policyTicket,
            )
        )
        return (timeout[0], policyTicket[0])

    def PolicySecret(
        self,
        authHandle,
        policySession,
        nonceTPM,
        cpHashA,
        policyRef,
        expiration,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        timeout = ffi.new("TPM2B_TIMEOUT **")
        policyTicket = ffi.new("TPMT_TK_AUTH **")
        _chkrc(
            lib.Esys_PolicySecret(
                self.ctx,
                authHandle,
                policySession,
                session1,
                session2,
                session3,
                nonceTPM,
                cpHashA,
                policyRef,
                expiration,
                timeout,
                policyTicket,
            )
        )
        return (timeout[0], policyTicket[0])

    def PolicyTicket(
        self,
        policySession,
        timeout,
        cpHashA,
        policyRef,
        authName,
        ticket,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyTicket(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                timeout,
                cpHashA,
                policyRef,
                authName,
                ticket,
            )
        )

    def PolicyOR(
        self,
        policySession,
        pHashList,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyOR(
                self.ctx, policySession, session1, session2, session3, pHashList
            )
        )

    def PolicyPCR(
        self,
        policySession,
        pcrDigest,
        pcrs,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyPCR(
                self.ctx, policySession, session1, session2, session3, pcrDigest, pcrs
            )
        )

    def PolicyLocality(
        self,
        policySession,
        locality,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyLocality(
                self.ctx, policySession, session1, session2, session3, locality
            )
        )

    def PolicyNV(
        self,
        authHandle,
        nvIndex,
        policySession,
        operandB,
        offset,
        operation,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyNV(
                self.ctx,
                authHandle,
                nvIndex,
                policySession,
                session1,
                session2,
                session3,
                operandB,
                offset,
                operation,
            )
        )

    def PolicyCounterTimer(
        self,
        policySession,
        operandB,
        offset,
        operation,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyCounterTimer(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                operandB,
                offset,
                operation,
            )
        )

    def PolicyCommandCode(
        self,
        policySession,
        code,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyCommandCode(
                self.ctx, policySession, session1, session2, session3, code
            )
        )

    def PolicyPhysicalPresence(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyPhysicalPresence(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyCpHash(
        self,
        policySession,
        cpHashA,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyCpHash(
                self.ctx, policySession, session1, session2, session3, cpHashA
            )
        )

    def PolicyNameHash(
        self,
        policySession,
        nameHash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyNameHash(
                self.ctx, policySession, session1, session2, session3, nameHash
            )
        )

    def PolicyDuplicationSelect(
        self,
        policySession,
        objectName,
        newParentName,
        includeObject,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyDuplicationSelect(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                objectName,
                newParentName,
                includeObject,
            )
        )

    def PolicyAuthorize(
        self,
        policySession,
        approvedPolicy,
        policyRef,
        keySign,
        checkTicket,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyAuthorize(
                self.ctx,
                policySession,
                session1,
                session2,
                session3,
                approvedPolicy,
                policyRef,
                keySign,
                checkTicket,
            )
        )

    def PolicyAuthValue(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyAuthValue(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyPassword(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyPassword(
                self.ctx, policySession, session1, session2, session3
            )
        )

    def PolicyGetDigest(
        self,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        policyDigest = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_PolicyGetDigest(
                self.ctx, policySession, session1, session2, session3, policyDigest
            )
        )
        return policyDigest[0]

    def PolicyNvWritten(
        self,
        policySession,
        writtenSet,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyNvWritten(
                self.ctx, policySession, session1, session2, session3, writtenSet
            )
        )

    def PolicyTemplate(
        self,
        policySession,
        templateHash,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyTemplate(
                self.ctx, policySession, session1, session2, session3, templateHash
            )
        )

    def PolicyAuthorizeNV(
        self,
        authHandle,
        nvIndex,
        policySession,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PolicyAuthorizeNV(
                self.ctx,
                authHandle,
                nvIndex,
                policySession,
                session1,
                session2,
                session3,
            )
        )

    def CreatePrimary(
        self,
        primaryHandle,
        inSensitive,
        inPublic,
        outsideInfo,
        creationPCR,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        objectHandle = ffi.new("ESYS_TR *")
        outPublic = ffi.new("TPM2B_PUBLIC **")
        creationData = ffi.new("TPM2B_CREATION_DATA **")
        creationHash = ffi.new("TPM2B_DIGEST **")
        creationTicket = ffi.new("TPMT_TK_CREATION **")
        _chkrc(
            lib.Esys_CreatePrimary(
                self.ctx,
                primaryHandle,
                session1,
                session2,
                session3,
                inSensitive._cdata,
                inPublic._cdata,
                outsideInfo._cdata,
                creationPCR._cdata,
                objectHandle,
                outPublic,
                creationData,
                creationHash,
                creationTicket,
            )
        )

        return (
            ESYS_TR(objectHandle[0]),
            TPM2B_PUBLIC(_cdata=outPublic[0]),
            TPM2B_CREATION_DATA(_cdata=creationData[0]),
            TPM2B_DIGEST(_cdata=creationHash[0]),
            TPMT_TK_CREATION(_cdata=creationTicket[0]),
        )

    def HierarchyControl(
        self,
        authHandle,
        enable,
        state,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_HierarchyControl(
                self.ctx, authHandle, session1, session2, session3, enable, state
            )
        )

    def SetPrimaryPolicy(
        self,
        authHandle,
        authPolicy,
        hashAlg,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_SetPrimaryPolicy(
                self.ctx, authHandle, session1, session2, session3, authPolicy, hashAlg
            )
        )

    def ChangePPS(
        self,
        authHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_ChangePPS(self.ctx, authHandle, session1, session2, session3))

    def ChangeEPS(
        self,
        authHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_ChangeEPS(self.ctx, authHandle, session1, session2, session3))

    def Clear(
        self,
        authHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_Clear(self.ctx, authHandle, session1, session2, session3))

    def ClearControl(
        self,
        auth,
        disable,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_ClearControl(self.ctx, auth, session1, session2, session3, disable)
        )

    def HierarchyChangeAuth(
        self,
        authHandle,
        newAuth,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_HierarchyChangeAuth(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                TPM2B_pack(newAuth, t="TPM2B_AUTH"),
            )
        )

    def DictionaryAttackLockReset(
        self,
        lockHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_DictionaryAttackLockReset(
                self.ctx, lockHandle, session1, session2, session3
            )
        )

    def DictionaryAttackParameters(
        self,
        lockHandle,
        newMaxTries,
        newRecoveryTime,
        lockoutRecovery,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_DictionaryAttackParameters(
                self.ctx,
                lockHandle,
                session1,
                session2,
                session3,
                newMaxTries,
                newRecoveryTime,
                lockoutRecovery,
            )
        )

    def PP_Commands(
        self,
        auth,
        setList,
        clearList,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_PP_Commands(
                self.ctx, auth, session1, session2, session3, setList, clearList
            )
        )

    def SetAlgorithmSet(
        self,
        authHandle,
        algorithmSet,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_SetAlgorithmSet(
                self.ctx, authHandle, session1, session2, session3, algorithmSet
            )
        )

    def FieldUpgradeStart(
        self,
        authorization,
        keyHandle,
        fuDigest,
        manifestSignature,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_FieldUpgradeStart(
                self.ctx,
                authorization,
                keyHandle,
                session1,
                session2,
                session3,
                fuDigest,
                manifestSignature,
            )
        )

    def FieldUpgradeData(
        self,
        fuData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        nextDigest = ffi.new("TPMT_HA **")
        firstDigest = ffi.new("TPMT_HA **")
        _chkrc(
            lib.Esys_FieldUpgradeData(
                self.ctx, session1, session2, session3, fuData, nextDigest, firstDigest
            )
        )
        return (nextDigest[0], firstDigest[0])

    def FirmwareRead(
        self,
        sequenceNumber,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        fuData = ffi.new("TPM2B_MAX_BUFFER **")
        _chkrc(
            lib.Esys_FirmwareRead(
                self.ctx, session1, session2, session3, sequenceNumber, fuData
            )
        )
        return fuData[0]

    def ContextSave(self, saveHandle):
        context = ffi.new("TPMS_CONTEXT **")
        _chkrc(lib.Esys_ContextSave(self.ctx, saveHandle, context))
        return context[0]

    def ContextLoad(self, context):
        loadedHandle = ffi.new("ESYS_TR *")
        _chkrc(lib.Esys_ContextLoad(self.ctx, context, loadedHandle))
        loadedHandleObject = loadedHandle[0]
        return loadedHandleObject

    def FlushContext(self, flushHandle):
        _chkrc(lib.Esys_FlushContext(self.ctx, flushHandle))

    def EvictControl(
        self,
        auth,
        objectHandle,
        persistentHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        newObjectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_EvictControl(
                self.ctx,
                auth,
                objectHandle,
                session1,
                session2,
                session3,
                persistentHandle,
                newObjectHandle,
            )
        )
        newObjectHandleObject = newObjectHandle[0]
        return newObjectHandleObject

    def ReadClock(
        self, session1=ESYS_TR.NONE, session2=ESYS_TR.NONE, session3=ESYS_TR.NONE
    ):

        currentTime = ffi.new("TPMS_TIME_INFO **")
        _chkrc(lib.Esys_ReadClock(self.ctx, session1, session2, session3, currentTime))
        return currentTime[0]

    def ClockSet(
        self,
        auth,
        newTime,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_ClockSet(self.ctx, auth, session1, session2, session3, newTime))

    def ClockRateAdjust(
        self,
        auth,
        rateAdjust,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_ClockRateAdjust(
                self.ctx, auth, session1, session2, session3, rateAdjust
            )
        )

    def GetCapability(
        self,
        capability,
        prop,
        propertyCount,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        moreData = ffi.new("TPMI_YES_NO *")
        capabilityData = ffi.new("TPMS_CAPABILITY_DATA **")
        _chkrc(
            lib.Esys_GetCapability(
                self.ctx,
                session1,
                session2,
                session3,
                capability,
                prop,
                propertyCount,
                moreData,
                capabilityData,
            )
        )
        return (moreData[0], capabilityData[0])

    def TestParms(
        self,
        parameters,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(lib.Esys_TestParms(self.ctx, session1, session2, session3, parameters))

    def NV_DefineSpace(
        self,
        authHandle,
        auth,
        publicInfo,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        nvHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_NV_DefineSpace(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                TPM2B_pack(auth, t="TPM2B_AUTH"),
                publicInfo._cdata,
                nvHandle,
            )
        )
        nvHandleObject = nvHandle[0]
        return nvHandleObject

    def NV_UndefineSpace(
        self,
        authHandle,
        nvIndex,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_UndefineSpace(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_UndefineSpaceSpecial(
        self,
        nvIndex,
        platform,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_UndefineSpaceSpecial(
                self.ctx, nvIndex, platform, session1, session2, session3
            )
        )

    def NV_ReadPublic(
        self,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        nvPublic = ffi.new("TPM2B_NV_PUBLIC **")
        nvName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_NV_ReadPublic(
                self.ctx, nvIndex, session1, session2, session3, nvPublic, nvName
            )
        )
        return (TPM2B_NV_PUBLIC(_cdata=nvPublic[0]), TPM2B_NAME(_cdata=nvName[0]))

    def NV_Write(
        self,
        nvIndex,
        data,
        offset=0,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex

        _chkrc(
            lib.Esys_NV_Write(
                self.ctx,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                TPM2B_pack(data, t="TPM2B_MAX_NV_BUFFER"),
                offset,
            )
        )

    def NV_Increment(
        self,
        authHandle,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_Increment(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_Extend(
        self,
        authHandle,
        nvIndex,
        data,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_Extend(
                self.ctx, authHandle, nvIndex, session1, session2, session3, data
            )
        )

    def NV_SetBits(
        self,
        authHandle,
        nvIndex,
        bits,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_SetBits(
                self.ctx, authHandle, nvIndex, session1, session2, session3, bits
            )
        )

    def NV_WriteLock(
        self,
        authHandle,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_WriteLock(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_GlobalWriteLock(
        self,
        authHandle,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_GlobalWriteLock(
                self.ctx, authHandle, session1, session2, session3
            )
        )

    def NV_Read(
        self,
        nvIndex,
        size,
        offset=0,
        authHandle=0,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if authHandle == 0:
            authHandle = nvIndex

        data = ffi.new("TPM2B_MAX_NV_BUFFER **")
        _chkrc(
            lib.Esys_NV_Read(
                self.ctx,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                size,
                offset,
                data,
            )
        )
        return TPM2B_unpack(data[0])

    def NV_ReadLock(
        self,
        authHandle,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_ReadLock(
                self.ctx, authHandle, nvIndex, session1, session2, session3
            )
        )

    def NV_ChangeAuth(
        self,
        nvIndex,
        newAuth,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        _chkrc(
            lib.Esys_NV_ChangeAuth(
                self.ctx, nvIndex, session1, session2, session3, newAuth
            )
        )

    def NV_Certify(
        self,
        signHandle,
        authHandle,
        nvIndex,
        qualifyingData,
        inScheme,
        size,
        offset,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        certifyInfo = ffi.new("TPM2B_ATTEST **")
        signature = ffi.new("TPMT_SIGNATURE **")
        _chkrc(
            lib.Esys_NV_Certify(
                self.ctx,
                signHandle,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                qualifyingData,
                inScheme,
                size,
                offset,
                certifyInfo,
                signature,
            )
        )
        return (certifyInfo[0], signature[0])

    def Vendor_TCG_Test(
        self,
        inputData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        outputData = ffi.new("TPM2B_DATA **")
        _chkrc(
            lib.Esys_Vendor_TCG_Test(
                self.ctx, session1, session2, session3, inputData, outputData
            )
        )
        return outputData[0]
