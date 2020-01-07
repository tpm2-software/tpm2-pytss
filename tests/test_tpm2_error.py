from contextlib import ExitStack
from tpm2_pytss.binding import *
from tpm2_pytss.exceptions import TPM2Error
from .base_esys import BaseTestESYS


class TestTPM2RC(BaseTestESYS):
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

            if tpm2err.rc != 0x1D5:
                raise Exception(
                    "Unexpected RC: %#x, expected %#x"
                    % (tpm2err.rc, TPM2_RC_SIZE + TPM2_RC_P + TPM2_RC_1)
                )
            if tpm2err.error != TPM2_RC_SIZE:
                raise Exception(
                    "Unexpected error: %#x, expected %#x"
                    % (tpm2err.error, TPM2_RC_SIZE)
                )
            if tpm2err.parameter != 1:
                raise Exception(
                    "Unexpected parameter: %u, expected 1" % tpm2err.parameter
                )
            if tpm2err.handle != 0:
                raise Exception("Unexpected handle: %u, expected 0" % tpm2err.handle)
            if tpm2err.session != 0:
                raise Exception("Unexpected session: %u, expected 0" % tpm2err.session)

    def test_tpm2_rc_handle(self):
        with ExitStack() as stack:
            tpm2err = TPM2Error(0)
            try:
                r = self.esys_ctx.PCR_Reset(
                    ESYS_TR_NONE, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE
                )
            except TPM2Error as e:
                tpm2err = e

            if tpm2err.rc != 0x184:
                raise Exception(
                    "Unexpected RC: %#x, expected %#x"
                    % (tpm2err.rc, TPM2_RC_VALUE + TPM2_RC_H + TPM2_RC_1)
                )
            if tpm2err.error != TPM2_RC_VALUE:
                raise Exception(
                    "Unexpected error: %#x, expected %#x"
                    % (tpm2err.error, TPM2_RC_VALUE)
                )
            if tpm2err.parameter != 0:
                raise Exception(
                    "Unexpected parameter: %u, expected 0" % tpm2err.parameter
                )
            if tpm2err.handle != 1:
                raise Exception("Unexpected handle: %u, expected 1" % tpm2err.handle)
            if tpm2err.session != 0:
                raise Exception("Unexpected session: %u, expected 0" % tpm2err.session)

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

            if tpm2err.rc != 0x982:
                raise Exception(
                    "Unexpected RC: %#x, expected %#x"
                    % (tpm2err.rc, TPM2_RC_ATTRIBUTES + TPM2_RC_S + TPM2_RC_1)
                )
            if tpm2err.error != TPM2_RC_ATTRIBUTES:
                raise Exception(
                    "Unexpected error: %#x, expected %#x"
                    % (tpm2err.error, TPM2_RC_VALUE)
                )
            if tpm2err.parameter != 0:
                raise Exception(
                    "Unexpected parameter: %u, expected 0" % tpm2err.parameter
                )
            if tpm2err.handle != 0:
                raise Exception("Unexpected handle: %u, expected 0" % tpm2err.handle)
            if tpm2err.session != 1:
                raise Exception("Unexpected session: %u, expected 1" % tpm2err.session)
