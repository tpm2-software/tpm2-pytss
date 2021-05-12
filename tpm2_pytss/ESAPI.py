"""
SPDX-License-Identifier: BSD-2
"""

from ._libtpm2_pytss import lib

from .types import *

from .utils import _chkrc, TPM2B_pack


def get_ptr(dptr):
    return ffi.gc(dptr[0], lib.Esys_Free)


def get_cdata(value, expected, varname, allow_none=False):
    tname = expected.__name__

    if value is None and allow_none:
        return ffi.NULL
    elif value is None:
        raise TypeError(f"expected {varname} to be {tname}, got None")

    if isinstance(value, ffi.CData):
        tipe = ffi.typeof(value)
        if tipe.kind == "pointer":
            tipe = tipe.item
        classname = fixup_classname(tipe)
        if classname != tname:
            raise TypeError(f"expected {varname} to be {tname}, got {tipe.cname}")
        return value

    vname = type(value).__name__
    if isinstance(value, bytes) and issubclass(expected, TPM2B_SIMPLE_OBJECT):
        bo = expected(value)
        return bo._cdata
    elif not isinstance(value, expected):
        raise TypeError(f"expected {varname} to be {tname}, got {vname}")

    return value._cdata


def check_handle_type(handle, varname):
    if not isinstance(handle, int):
        raise TypeError(
            f"expected {varname} to be type int aka ESYS_TR, got {type(handle)}"
        )


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
        return TPM2B_NAME(_cdata=get_ptr(name))

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
        return TPML_ALG(get_ptr(toDoList))

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
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2_RC(testResult[0]))

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
            TPM2B_PRIVATE(get_ptr(outPrivate)),
            TPM2B_PUBLIC(get_ptr(outPublic)),
            TPM2B_CREATION_DATA(get_ptr(creationData)),
            TPM2B_DIGEST(get_ptr(creationHash)),
            TPMT_TK_CREATION(get_ptr(creationTicket)),
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
        inPrivate_cdata = get_cdata(
            inPrivate, TPM2B_SENSITIVE, "inPrivate", allow_none=True
        )
        inPublic_cdata = get_cdata(inPublic, TPM2B_PUBLIC, "inPublic")
        objectHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_LoadExternal(
                self.ctx,
                session1,
                session2,
                session3,
                inPrivate_cdata,
                inPublic_cdata,
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
            TPM2B_PUBLIC(get_ptr(outPublic)),
            TPM2B_NAME(get_ptr(name)),
            TPM2B_NAME(get_ptr(qualifiedName)),
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
        return TPM2B_DIGEST(get_ptr(certInfo))

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
        return (
            TPM2B_ID_OBJECT(get_ptr(credentialBlob)),
            TPM2B_ENCRYPTED_SECRET(get_ptr(secret)),
        )

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
        return TPM2B_SENSITIVE_DATA(get_ptr(outData))

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
        return TPM2B_PRIVATE(get_ptr(outPrivate))

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
            TPM2B_PRIVATE(get_ptr(outPrivate)),
            TPM2B_PUBLIC(get_ptr(outPublic)),
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
        return (get_ptr(encryptionKeyOut), get_ptr(duplicate), get_ptr(outSymSeed))

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
        return (get_ptr(outDuplicate), get_ptr(outSymSeed))

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
        return get_ptr(outPrivate)

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
        return TPM2B_PUBLIC_KEY_RSA(get_ptr(outData))

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
        return TPM2B_PUBLIC_KEY_RSA(get_ptr(message))

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
        return (TPM2B_ECC_POINT(get_ptr(zPoint)), TPM2B_ECC_POINT(get_ptr(pubPoint)))

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
        return TPM2B_ECC_POINT(get_ptr(outPoint))

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
        return TPMS_ALGORITHM_DETAIL_ECC(get_ptr(parameters))

    def ZGen_2Phase(
        self,
        keyA,
        inQsB,
        inQeB,
        inScheme,
        counter,
        session1=ESYS_TR.PASSWORD,
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
                inQsB._cdata,
                inQeB._cdata,
                inScheme,
                counter,
                outZ1,
                outZ2,
            )
        )

        return (TPM2B_ECC_POINT(get_ptr(outZ1)), TPM2B_ECC_POINT(get_ptr(outZ2)))

    def EncryptDecrypt(
        self,
        keyHandle,
        decrypt,
        mode,
        ivIn,
        inData,
        session1=ESYS_TR.PASSWORD,
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
                ivIn._cdata,
                inData._cdata,
                outData,
                ivOut,
            )
        )
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2B_IV(get_ptr(ivOut)))

    def EncryptDecrypt2(
        self,
        keyHandle,
        decrypt,
        mode,
        ivIn,
        inData,
        session1=ESYS_TR.PASSWORD,
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
                inData._cdata,
                decrypt,
                mode,
                ivIn._cdata,
                outData,
                ivOut,
            )
        )
        return (TPM2B_MAX_BUFFER(get_ptr(outData)), TPM2B_IV(get_ptr(ivOut)))

    def Hash(
        self,
        data,
        hashAlg,
        hierarchy=ESYS_TR.OWNER,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(data, (bytes, str)):
            data = TPM2B_MAX_BUFFER(data)

        outHash = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_Hash(
                self.ctx,
                session1,
                session2,
                session3,
                data._cdata,
                hashAlg,
                hierarchy,
                outHash,
                validation,
            )
        )
        return (TPM2B_DIGEST(get_ptr(outHash)), TPMT_TK_HASHCHECK(get_ptr(validation)))

    def HMAC(
        self,
        handle,
        buffer,
        hashAlg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(buffer, (bytes, str)):
            buffer = TPM2B_MAX_BUFFER(buffer)

        outHMAC = ffi.new("TPM2B_DIGEST **")
        _chkrc(
            lib.Esys_HMAC(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                buffer._cdata,
                hashAlg,
                outHMAC,
            )
        )
        return TPM2B_DIGEST(get_ptr(outHMAC))

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

        return TPM2B_DIGEST(get_ptr(randomBytes))

    def StirRandom(
        self,
        inData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(inData, (bytes, str)):
            inData = TPM2B_SENSITIVE_DATA(inData)

        _chkrc(
            lib.Esys_StirRandom(self.ctx, session1, session2, session3, inData._cdata)
        )

    def HMAC_Start(
        self,
        handle,
        auth,
        hashAlg,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(auth, (str, bytes)):
            auth = TPM2B_AUTH(auth)
        elif auth is None:
            auth = TPM2B_AUTH()

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HMAC_Start(
                self.ctx,
                handle,
                session1,
                session2,
                session3,
                auth._cdata,
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

        if isinstance(auth, (str, bytes)):
            auth = TPM2B_AUTH(auth)
        elif auth is None:
            auth = TPM2B_AUTH()

        sequenceHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_HashSequenceStart(
                self.ctx,
                session1,
                session2,
                session3,
                auth._cdata,
                hashAlg,
                sequenceHandle,
            )
        )
        sequenceHandleObject = sequenceHandle[0]
        return sequenceHandleObject

    def SequenceUpdate(
        self,
        sequenceHandle,
        buffer,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(buffer, (str, bytes)):
            buffer = TPM2B_MAX_BUFFER(buffer)
        elif buffer is None:
            buffer = TPM2B_MAX_BUFFER()

        _chkrc(
            lib.Esys_SequenceUpdate(
                self.ctx, sequenceHandle, session1, session2, session3, buffer._cdata
            )
        )

    def SequenceComplete(
        self,
        sequenceHandle,
        buffer,
        hierarchy=ESYS_TR.OWNER,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(buffer, (str, bytes)):
            buffer = TPM2B_MAX_BUFFER(buffer)
        elif buffer is None:
            buffer = TPM2B_MAX_BUFFER()

        result = ffi.new("TPM2B_DIGEST **")
        validation = ffi.new("TPMT_TK_HASHCHECK **")
        _chkrc(
            lib.Esys_SequenceComplete(
                self.ctx,
                sequenceHandle,
                session1,
                session2,
                session3,
                buffer._cdata,
                hierarchy,
                result,
                validation,
            )
        )

        return (TPM2B_DIGEST(get_ptr(result)), TPMT_TK_HASHCHECK(get_ptr(validation)))

    def EventSequenceComplete(
        self,
        pcrHandle,
        sequenceHandle,
        buffer,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        if isinstance(buffer, (str, bytes)):
            buffer = TPM2B_MAX_BUFFER(buffer)
        elif buffer is None:
            buffer = TPM2B_MAX_BUFFER()

        results = ffi.new("TPML_DIGEST_VALUES **")
        _chkrc(
            lib.Esys_EventSequenceComplete(
                self.ctx,
                pcrHandle,
                sequenceHandle,
                session1,
                session2,
                session3,
                buffer._cdata,
                results,
            )
        )
        return TPML_DIGEST_VALUES(get_ptr(results))

    def Certify(
        self,
        objectHandle,
        signHandle,
        qualifyingData,
        inScheme,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.PASSWORD,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(objectHandle, "objectHandle")
        check_handle_type(signHandle, "signHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifyingData, TPM2B_DATA, "qualifyingData")
        inScheme_cdata = get_cdata(inScheme, TPMT_SIG_SCHEME, "inScheme")

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
                qualifyingData_cdata,
                inScheme_cdata,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def CertifyCreation(
        self,
        signHandle,
        objectHandle,
        qualifyingData,
        creationHash,
        inScheme,
        creationTicket,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(objectHandle, "objectHandle")
        check_handle_type(signHandle, "signHandle")
        check_handle_type(session1, "session1")
        check_handle_type(session2, "session2")
        check_handle_type(session3, "session3")

        qualifyingData_cdata = get_cdata(qualifyingData, TPM2B_DATA, "qualifyingData")
        inScheme_cdata = get_cdata(inScheme, TPMT_SIG_SCHEME, "inScheme")
        creationHash_cdata = get_cdata(creationHash, TPM2B_DIGEST, "creationHash")
        creationTicket_cdata = get_cdata(
            creationTicket, TPMT_TK_CREATION, "creationTicket"
        )

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
                qualifyingData_cdata,
                creationHash_cdata,
                inScheme_cdata,
                creationTicket_cdata,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

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
        return (get_ptr(quoted), get_ptr(signature))

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
        return (get_ptr(auditInfo), get_ptr(signature))

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
        return (get_ptr(auditInfo), get_ptr(signature))

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
        return (get_ptr(timeInfo), get_ptr(signature))

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
        return (get_ptr(K), get_ptr(L), get_ptr(E), counter[0])

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
        return (TPM2B_ECC_POINT(get_ptr(Q)), counter[0])

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
        return get_ptr(validation)

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
        return get_ptr(signature)

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
        return get_ptr(digests)

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
            TPML_PCR_SELECTION(_cdata=get_ptr(pcrSelectionOut)),
            TPML_DIGEST(_cdata=get_ptr(pcrValues)),
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
        return (get_ptr(timeout), get_ptr(policyTicket))

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
        return (get_ptr(timeout), get_ptr(policyTicket))

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
        return get_ptr(policyDigest)

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
            TPM2B_PUBLIC(_cdata=get_ptr(outPublic)),
            TPM2B_CREATION_DATA(_cdata=get_ptr(creationData)),
            TPM2B_DIGEST(_cdata=get_ptr(creationHash)),
            TPMT_TK_CREATION(_cdata=get_ptr(creationTicket)),
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
        return (get_ptr(nextDigest), get_ptr(firstDigest))

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
        return get_ptr(fuData)

    def ContextSave(self, saveHandle):
        context = ffi.new("TPMS_CONTEXT **")
        _chkrc(lib.Esys_ContextSave(self.ctx, saveHandle, context))
        return get_ptr(context)

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
        return get_ptr(currentTime)

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
        return (bool(moreData[0]), TPMS_CAPABILITY_DATA(get_ptr(capabilityData)))

    def TestParms(
        self,
        parameters,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        parameters_cdata = get_cdata(parameters, TPMT_PUBLIC_PARMS, "parameters")
        _chkrc(
            lib.Esys_TestParms(self.ctx, session1, session2, session3, parameters_cdata)
        )

    def NV_DefineSpace(
        self,
        authHandle,
        auth,
        publicInfo,
        session1=ESYS_TR.PASSWORD,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(authHandle, "authHandle")
        auth_cdata = get_cdata(auth, TPM2B_AUTH, "auth", allow_none=True)
        publicInfo_cdata = get_cdata(publicInfo, TPM2B_NV_PUBLIC, "publicInfo")
        nvHandle = ffi.new("ESYS_TR *")
        _chkrc(
            lib.Esys_NV_DefineSpace(
                self.ctx,
                authHandle,
                session1,
                session2,
                session3,
                auth_cdata,
                publicInfo_cdata,
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

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
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

        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(platform, "platform")
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

        check_handle_type(nvIndex, "nvIndex")
        nvPublic = ffi.new("TPM2B_NV_PUBLIC **")
        nvName = ffi.new("TPM2B_NAME **")
        _chkrc(
            lib.Esys_NV_ReadPublic(
                self.ctx, nvIndex, session1, session2, session3, nvPublic, nvName
            )
        )
        return (
            TPM2B_NV_PUBLIC(_cdata=get_ptr(nvPublic)),
            TPM2B_NAME(_cdata=get_ptr(nvName)),
        )

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
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Write(
                self.ctx,
                authHandle,
                nvIndex,
                session1,
                session2,
                session3,
                data_cdata,
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

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
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

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        data_cdata = get_cdata(data, TPM2B_MAX_NV_BUFFER, "data")
        _chkrc(
            lib.Esys_NV_Extend(
                self.ctx, authHandle, nvIndex, session1, session2, session3, data_cdata
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

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
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

        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
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

        check_handle_type(authHandle, "authHandle")
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
        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
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
        return TPM2B_MAX_NV_BUFFER(get_ptr(data))

    def NV_ReadLock(
        self,
        authHandle,
        nvIndex,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):

        check_handle_type(nvIndex, "nvIndex")
        check_handle_type(authHandle, "authHandle")
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

        check_handle_type(nvIndex, "nvIndex")
        newAuth_cdata = get_cdata(newAuth, TPM2B_DIGEST, "newAuth")
        _chkrc(
            lib.Esys_NV_ChangeAuth(
                self.ctx, nvIndex, session1, session2, session3, newAuth_cdata
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

        check_handle_type(signHandle, "signHandle")
        check_handle_type(authHandle, "authHandle")
        check_handle_type(nvIndex, "nvIndex")
        qualifyingData_cdata = get_cdata(qualifyingData, TPM2B_DATA, "qualifyingData")
        inScheme_cdata = get_cdata(inScheme, TPMT_SIG_SCHEME, "inScheme")
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
                qualifyingData_cdata,
                inScheme_cdata,
                size,
                offset,
                certifyInfo,
                signature,
            )
        )
        return (TPM2B_ATTEST(get_ptr(certifyInfo)), TPMT_SIGNATURE(get_ptr(signature)))

    def Vendor_TCG_Test(
        self,
        inputData,
        session1=ESYS_TR.NONE,
        session2=ESYS_TR.NONE,
        session3=ESYS_TR.NONE,
    ):
        inputData_cdata = get_cdata(inputData, TPM2B_DATA, "inputData")
        outputData = ffi.new("TPM2B_DATA **")
        _chkrc(
            lib.Esys_Vendor_TCG_Test(
                self.ctx, session1, session2, session3, inputData_cdata, outputData
            )
        )
        return TPM2B_DATA(get_ptr(outputData))
