from contextlib import ExitStack

from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestESYS
from tpm2_pytss.exceptions import TPM2Error


class TestGetTime(BaseTestESYS):
    def test_get_time(self):
        with ExitStack() as stack:

            authValuePrimary = TPM2B_AUTH(size=5, buffer=[1, 2, 3, 4, 5])

            inSensitivePrimary = TPM2B_SENSITIVE_CREATE(
                size=0,
                sensitive=TPMS_SENSITIVE_CREATE(
                    userAuth=TPM2B_AUTH(size=0, buffer=[0]),
                    data=TPM2B_SENSITIVE_DATA(size=0, buffer=[0]),
                ),
            )

            inSensitivePrimary.sensitive.userAuth = authValuePrimary

            inPublic = TPM2B_PUBLIC(
                size=0,
                publicArea=TPMT_PUBLIC(
                    type=TPM2_ALG_RSA,
                    nameAlg=TPM2_ALG_SHA1,
                    objectAttributes=(
                        TPMA_OBJECT_USERWITHAUTH
                        | TPMA_OBJECT_RESTRICTED
                        | TPMA_OBJECT_SIGN_ENCRYPT
                        | TPMA_OBJECT_FIXEDTPM
                        | TPMA_OBJECT_FIXEDPARENT
                        | TPMA_OBJECT_SENSITIVEDATAORIGIN
                    ),
                    authPolicy=TPM2B_DIGEST(size=0),
                    parameters=TPMU_PUBLIC_PARMS(
                        rsaDetail=TPMS_RSA_PARMS(
                            symmetric=TPMT_SYM_DEF_OBJECT(
                                algorithm=TPM2_ALG_NULL,
                                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                                mode=TPMU_SYM_MODE(aes=TPM2_ALG_CFB),
                            ),
                            scheme=TPMT_RSA_SCHEME(
                                scheme=TPM2_ALG_RSASSA,
                                details=TPMU_ASYM_SCHEME(
                                    rsassa=TPMS_SIG_SCHEME_RSASSA(hashAlg=TPM2_ALG_SHA1)
                                ),
                            ),
                            keyBits=2048,
                            exponent=0,
                        )
                    ),
                    unique=TPMU_PUBLIC_ID(rsa=TPM2B_PUBLIC_KEY_RSA(size=0, buffer={})),
                ),
            )

            authValue = TPM2B_AUTH(size=0, buffer=[])

            outsideInfo = TPM2B_DATA(size=0, buffer=[])

            creationPCR = TPML_PCR_SELECTION(count=0)

            self.esys_ctx.TR_SetAuth(ESYS_TR_RH_OWNER, authValue)

            signHandle = stack.enter_context(self.esys_ctx.flush_tr())

            (
                outPublic_ptr_ptr,
                creationData_ptr_ptr,
                creationHash_ptr_ptr,
                creationTicket_ptr_ptr,
            ) = self.esys_ctx.CreatePrimary(
                ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                inSensitivePrimary,
                inPublic,
                outsideInfo,
                creationPCR,
                signHandle,
            )

            self.esys_ctx.TR_SetAuth(signHandle, authValuePrimary)

            privacyAdminHandle = ESYS_TR_RH_ENDORSEMENT
            inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG_NULL)
            qualifyingData = TPM2B_DATA(size=0, buffer=[0])

            try:
                (timeInfo_ptr_ptr, signature_ptr_ptr) = self.esys_ctx.GetTime(
                    privacyAdminHandle,
                    signHandle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    qualifyingData,
                    inScheme,
                )
            except TPM2Error as error:
                if (
                    (error.rc == TPM2_RC_COMMAND_CODE)
                    or (error.rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
                    or (error.rc == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))
                ):
                    self.skipTest("Command TPM2_GetTime not supported by TPM")
                raise
