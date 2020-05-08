from contextlib import ExitStack

from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestESYS


class TestAutoSessionFlags(BaseTestESYS):
    def test_auto_session_flags(self):
        with ExitStack() as stack:

            symmetric = TPMT_SYM_DEF(
                algorithm=TPM2_ALG_AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG_CFB),
            )

            nonceCaller = TPM2B_NONCE(
                size=20,
                buffer=[
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    10,
                    11,
                    12,
                    13,
                    14,
                    15,
                    16,
                    17,
                    18,
                    19,
                    20,
                ],
            )

            symmetric_ptr = stack.enter_context(symmetric.ptr())
            nonceCaller_ptr = stack.enter_context(nonceCaller.ptr())

            # Auth session
            session_auth = stack.enter_context(
                self.esys_ctx.auth_session(
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    nonceCaller_ptr,
                    TPM2_SE_HMAC,
                    symmetric_ptr,
                    TPM2_ALG_SHA1,
                )
            )

            # Enc param session
            session_enc = stack.enter_context(
                self.esys_ctx.auth_session(
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    nonceCaller_ptr,
                    TPM2_SE_HMAC,
                    symmetric_ptr,
                    TPM2_ALG_SHA1,
                )
            )

            # Set both ENC and DEC flags for the enc session
            sessionAttributes = (
                TPMA_SESSION_DECRYPT
                | TPMA_SESSION_ENCRYPT
                | TPMA_SESSION_CONTINUESESSION
            )

            self.esys_ctx.TRSess_SetAttributes(session_enc, sessionAttributes, 0xFF)

            auth = TPM2B_AUTH(
                size=20,
                buffer=[
                    10,
                    11,
                    12,
                    13,
                    14,
                    15,
                    16,
                    17,
                    18,
                    19,
                    20,
                    21,
                    22,
                    23,
                    24,
                    25,
                    26,
                    27,
                    28,
                    29,
                ],
            )

            # TODO Move this into binding
            import ctypes

            attributes = ctypes.c_uint32(
                TPMA_NV_OWNERWRITE
                | TPMA_NV_AUTHWRITE
                | TPMA_NV_WRITE_STCLEAR
                | TPMA_NV_READ_STCLEAR
                | TPMA_NV_AUTHREAD
                | TPMA_NV_OWNERREAD
            ).value

            publicInfo = TPM2B_NV_PUBLIC(
                size=0,
                nvPublic=TPMS_NV_PUBLIC(
                    nvIndex=TPM2_NV_INDEX_FIRST,
                    nameAlg=TPM2_ALG_SHA1,
                    attributes=attributes,
                    authPolicy=TPM2B_DIGEST(size=0, buffer=[]),
                    dataSize=20,
                ),
            )

            auth_ptr = stack.enter_context(auth.ptr())
            publicInfo_ptr = stack.enter_context(publicInfo.ptr())

            nvHandle = stack.enter_context(
                self.esys_ctx.nv(
                    authHandle=ESYS_TR_RH_OWNER,
                    shandle1=session_auth,
                    auth=auth_ptr,
                    publicInfo=publicInfo_ptr,
                )
            )

            nv_test_data = TPM2B_MAX_NV_BUFFER(
                size=20,
                buffer=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            )
            nv_test_data_ptr = stack.enter_context(nv_test_data.ptr())

            # NV_Write cmd does not support TPMA_SESSION_ENCRYPT - the flag
            # should be auto cleared by ESYS
            r = self.esys_ctx.NV_Write(
                nvHandle,
                nvHandle,
                session_enc,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                nv_test_data_ptr,
                0,
            )

            # Verify that the same session flags are still set after the test
            sessionAttributesVerify_ptr = stack.enter_context(TPMA_SESSION_PTR())
            r = self.esys_ctx.TRSess_GetAttributes(
                session_enc, sessionAttributesVerify_ptr
            )

            if sessionAttributes != sessionAttributesVerify_ptr.value:
                raise Exception(
                    "Session flags not equal after write %x, %x"
                    % (sessionAttributes, sessionAttributesVerify_ptr.value)
                )

            data_ptr_ptr = stack.enter_context(TPM2B_MAX_NV_BUFFER_PTR_PTR())

            # NV_Read cmd does not support TPMA_SESSION_DECRYPT - the flags
            # should be auto cleared by ESYS
            r = self.esys_ctx.NV_Read(
                nvHandle,
                nvHandle,
                session_enc,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                20,
                0,
                data_ptr_ptr,
            )
            # TODO free data_ptr_ptr ?
            # free(data);

            # Verify that the same session flags are still set after the test
            self.esys_ctx.TRSess_GetAttributes(session_enc, sessionAttributesVerify_ptr)

            if sessionAttributes != sessionAttributesVerify_ptr.value:
                raise Exception(
                    "Session flags not equal after read %x, %x"
                    % (sessionAttributes, sessionAttributesVerify_ptr.value)
                )
