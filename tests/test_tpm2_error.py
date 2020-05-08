from contextlib import ExitStack
from tpm2_pytss.binding import *
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.util.testing import BaseTestESYS


class TestTPM2RC(BaseTestESYS):
    def check_error(self, tpm2err, rc, error, parameter, handle, session):
        self.assertEqual(
            tpm2err.rc, rc, "Unexpected RC: %#x, expected %#x" % (tpm2err.rc, rc)
        )
        self.assertEqual(
            tpm2err.error,
            error,
            "Unexpected error: %#x, expected %#x" % (tpm2err.error, error,),
        )
        self.assertEqual(
            tpm2err.parameter,
            parameter,
            "Unexpected parameter: %u, expected %u" % (tpm2err.parameter, parameter,),
        )
        self.assertEqual(
            tpm2err.handle,
            handle,
            "Unexpected handle: %u, expected %u" % (tpm2err.handle, handle,),
        )
        self.assertEqual(
            tpm2err.session,
            session,
            "Unexpected session: %u, expected %u" % (tpm2err.session, session,),
        )

    def test_tpm2_rc_attribute(self):
        with ExitStack() as stack:
            tpm2err = TPM2Error(0)
            try:
                rbytes = b"\x00" * 129
                rnd = TPM2B_SENSITIVE_DATA(buffer=rbytes)
                r = self.esys_ctx.StirRandom(
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, rnd
                )
            except TPM2Error as e:
                tpm2err = e

            self.check_error(
                tpm2err, TPM2_RC_SIZE + TPM2_RC_P + TPM2_RC_1, TPM2_RC_SIZE, 1, 0, 0
            )

    def test_tpm2_rc_handle(self):
        with ExitStack() as stack:
            tpm2err = TPM2Error(0)
            try:
                r = self.esys_ctx.PCR_Reset(
                    ESYS_TR_NONE, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE
                )
            except TPM2Error as e:
                tpm2err = e

            self.check_error(
                tpm2err, TPM2_RC_VALUE + TPM2_RC_H + TPM2_RC_1, TPM2_RC_VALUE, 0, 1, 0
            )

    def test_tpm2_rc_session(self):
        with ExitStack() as stack:
            tpm2err = TPM2Error(0)
            try:
                nbytes = b"\xFF" * 16
                ncaller = TPM2B_NONCE(buffer=nbytes)
                symmetric = TPMT_SYM_DEF(algorithm=TPM2_ALG_NULL)
                shandle = stack.enter_context(self.esys_ctx.flush_tr())
                r = self.esys_ctx.StartAuthSession(
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ncaller,
                    TPM2_SE_POLICY,
                    symmetric,
                    TPM2_ALG_SHA256,
                    shandle,
                )

                rnd = TPM2B_SENSITIVE_DATA(buffer=nbytes)
                r = self.esys_ctx.StirRandom(shandle, ESYS_TR_NONE, ESYS_TR_NONE, rnd)

            except TPM2Error as e:
                tpm2err = e

            self.check_error(
                tpm2err,
                TPM2_RC_ATTRIBUTES + TPM2_RC_S + TPM2_RC_1,
                TPM2_RC_ATTRIBUTES,
                0,
                0,
                1,
            )
