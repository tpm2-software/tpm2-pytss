from contextlib import ExitStack

from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestESYS
from tpm2_pytss.exceptions import TPM2Error


class TestAudit(BaseTestESYS):
    def test_audit(self):
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
                outPublic,
                creationData,
                creationHash,
                creationTicket,
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

            # /* Start a audit session */
            sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT
            sessionType = TPM2_SE_HMAC
            authHash = TPM2_ALG_SHA256
            symmetric = TPMT_SYM_DEF(algorithm=TPM2_ALG_NULL)

            session = stack.enter_context(
                self.esys_ctx.auth_session(
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    None,
                    sessionType,
                    symmetric,
                    authHash,
                )
            )

            self.esys_ctx.TRSess_SetAttributes(session, sessionAttributes, 0xFF)

            # Execute one command to be audited
            capability = TPM2_CAP_TPM_PROPERTIES
            prop = TPM2_PT_LOCKOUT_COUNTER
            propertyCount = 1

            moreData_ptr = TPMI_YES_NO_PTR(False)

            capabilityData_ptr = TPMS_CAPABILITY_DATA_PTR()

            capabilityData_ptr_ptr = self.esys_ctx.GetCapability(
                session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                capability,
                prop,
                propertyCount,
                moreData_ptr,
            )

            privacyHandle = ESYS_TR_RH_ENDORSEMENT
            qualifyingData = TPM2B_DATA(length=0, buffer=[])
            inScheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG_NULL)

            # Test the audit commands
            try:
                (
                    auditInfo_ptr_ptr,
                    signature_ptr_ptr,
                ) = self.esys_ctx.GetCommandAuditDigest(
                    privacyHandle,
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
                    self.skipTest(
                        "Command TPM2_GetCommandAuditDigest not supported by TPM."
                    )

            self.esys_ctx.GetSessionAuditDigest(
                privacyHandle,
                signHandle,
                session,
                ESYS_TR_PASSWORD,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                qualifyingData,
                inScheme,
                auditInfo_ptr_ptr,
                signature_ptr_ptr,
            )

            auditAlg = TPM2_ALG_SHA1
            clearList = TPML_CC()
            setList = TPML_CC()

            try:
                self.esys_ctx.SetCommandCodeAuditStatus(
                    ESYS_TR_RH_PLATFORM,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    auditAlg,
                    clearList,
                    setList,
                )
            except TPM2Error as error:
                if (error.rc & ~TPM2_RC_N_MASK) == TPM2_RC_BAD_AUTH:
                    # Platform authorization not possible test will be skipped
                    self.skipTest("Platform authorization not possible.")
