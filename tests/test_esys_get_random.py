import random
from contextlib import ExitStack

from tpm2_pytss.binding import *
from tpm2_pytss.esys import InvalidArgumentError
from tpm2_pytss.util.testing import BaseTestESYS


class TestGetRandom(BaseTestESYS):
    def test_random_length(self):
        length = random.randint(8, 32)

        array = self.esys_ctx.get_random(length)

        self.assertEqual(length, len(array))

    def test_invalid_length(self):
        with self.assertRaises(InvalidArgumentError):
            self.esys_ctx.get_random(65)

    def test_start_auth_session(self):
        with ExitStack() as stack:

            symmetric = TPMT_SYM_DEF(
                algorithm=TPM2_ALG_AES,
                keyBits=TPMU_SYM_KEY_BITS(aes=128),
                mode=TPMU_SYM_MODE(aes=TPM2_ALG_CFB),
            )

            symmetric_ptr = stack.enter_context(symmetric.ptr())

            session = stack.enter_context(
                self.esys_ctx.auth_session(
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    None,
                    TPM2_SE_HMAC,
                    symmetric_ptr,
                    TPM2_ALG_SHA1,
                )
            )

            self.esys_ctx.TRSess_SetAttributes(
                session, TPMA_SESSION_AUDIT, TPMA_SESSION_AUDIT
            )

            length = 48

            array = self.esys_ctx.get_random(length, shandle1=session)

            self.assertEqual(length, len(array))
