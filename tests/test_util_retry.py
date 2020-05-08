import time
import unittest
import unittest.mock

from tpm2_pytss import tcti
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.util.retry import retry_tcti_loop, retry_tcti_catch, TCTI_RETRY_TRIES


class TestTCTIRetry(unittest.TestCase):
    def test_tcti_retry_failure(self):
        self.tcti = tcti.TCTI.load("mssim")
        self.tcti_config = "port=-1"
        with unittest.mock.patch(
            "tpm2_pytss.esys.ESYSBinding.Tss2_TctiLdr_Initialize_Ex",
            side_effect=TPM2Error(655370),
        ), unittest.mock.patch("time.sleep", return_value=True):
            with self.assertRaises(TPM2Error):
                for retry in retry_tcti_loop():
                    with retry_tcti_catch(retry):
                        with self.tcti(config=self.tcti_config) as _tcti_ctx:
                            pass
            self.assertEqual(retry.i, TCTI_RETRY_TRIES)

    def test_tcti_retry_success(self):
        self.tcti = tcti.TCTI.load("mssim")
        self.tcti_config = "port=-1"
        with unittest.mock.patch(
            "tpm2_pytss.esys.ESYSBinding.Tss2_TctiLdr_Initialize_Ex", return_value=0
        ):
            for retry in retry_tcti_loop():
                with retry_tcti_catch(retry):
                    with self.tcti(config=self.tcti_config) as _tcti_ctx:
                        pass
            self.assertEqual(retry.i, 0)
