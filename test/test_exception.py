import unittest

from tpm2_pytss import TSS2_Exception, TPM2_RC, TSS2_RC


class ExceptionTest(unittest.TestCase):
    def test_non_fmt1(self):
        exc = TSS2_Exception(TPM2_RC.SESSION_HANDLES)
        self.assertEqual(exc.rc, TPM2_RC.SESSION_HANDLES)
        self.assertEqual(exc.error, TPM2_RC.SESSION_HANDLES)
        self.assertEqual(exc.handle, 0)
        self.assertEqual(exc.parameter, 0)
        self.assertEqual(exc.session, 0)

    def test_handle(self):
        rc = TPM2_RC.TYPE + TPM2_RC.H + TPM2_RC.RC1
        exc = TSS2_Exception(rc)
        self.assertEqual(exc.rc, rc)
        self.assertEqual(exc.error, TPM2_RC.TYPE)
        self.assertEqual(exc.handle, 1)
        self.assertEqual(exc.parameter, 0)
        self.assertEqual(exc.session, 0)

    def test_parameter(self):
        rc = TPM2_RC.ATTRIBUTES + TPM2_RC.P + TPM2_RC.RC1
        exc = TSS2_Exception(rc)
        self.assertEqual(exc.rc, rc)
        self.assertEqual(exc.error, TPM2_RC.ATTRIBUTES)
        self.assertEqual(exc.handle, 0)
        self.assertEqual(exc.parameter, 1)
        self.assertEqual(exc.session, 0)

    def test_session(self):
        rc = TPM2_RC.EXPIRED + TPM2_RC.S + TPM2_RC.RC1
        exc = TSS2_Exception(rc)
        self.assertEqual(exc.rc, rc)
        self.assertEqual(exc.error, TPM2_RC.EXPIRED)
        self.assertEqual(exc.handle, 0)
        self.assertEqual(exc.parameter, 0)
        self.assertEqual(exc.session, 1)

    def test_fmt1(self):
        rc = TPM2_RC.EXPIRED + TPM2_RC.S + TPM2_RC.RC1
        exc = TSS2_Exception(rc)
        self.assertEqual(exc.fmt1, True)

        exc = TSS2_Exception(TPM2_RC.SESSION_HANDLES)
        self.assertEqual(exc.fmt1, False)

    def test_input_types(self):
        self.assertEqual(
            str(TSS2_Exception(TPM2_RC.NV_LOCKED)), "tpm:error(2.0): NV access locked"
        )
        self.assertEqual(
            str(TSS2_Exception(TSS2_RC.ESYS_RC_BAD_VALUE)),
            "esapi:A parameter has a bad value",
        )
        self.assertEqual(
            str(TSS2_Exception(0x7000B)), "esapi:A parameter has a bad value"
        )


if __name__ == "__main__":
    unittest.main()
