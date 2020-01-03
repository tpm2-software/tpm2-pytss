from contextlib import ExitStack
from tpm2_pytss.binding import *
from tpm2_pytss.exceptions import TPM2Error
from .base_esys import BaseTestESYS


class TestTPM2RC(BaseTestESYS):
    def test_tpm2_rc_attribute(self):
        with ExitStack() as stack:
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
