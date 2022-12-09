#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

import unittest
from tpm2_pytss import *

try:
    from tpm2_pytss.TCTISPIHelper import TCTISPIHelper
except NotImplementedError:
    raise unittest.SkipTest("TCTISPIHelper not supported, skipping.")


class MySPITcti(TCTISPIHelper):

    TPM_DID_VID_HEAD = 0
    TPM_DID_VID_BODY = 1
    TPM_ACCESS_HEAD = 2
    TPM_ACCESS_BODY = 3
    TPM_STS_HEAD = 4
    TPM_STS_BODY = 5
    TPM_RID_HEAD = 6
    TPM_RID_BODY = 7

    TPM_DID_VID_0 = b"\x83\xd4\x0f\00\xd1\x15\x1b\x00"
    TPM_ACCESS_0 = b"\x80\xd4\x00\x00\xa1"
    TPM_STS_0 = b"\x83\xd4\x00\x18\x40\x00\x00\x00"
    TPM_RID_0 = b"\x80\xd4\x0f\x04\x00"

    def __init__(self, *args, with_exception=None, **kwargs):
        # Example of setting userdata, can be anything. You want
        # bound to this class, you can even add arguments, etc.
        self.with_exception = with_exception

        self.tpm_state = MySPITcti.TPM_DID_VID_HEAD

        # call the superclass
        super().__init__(*args, **kwargs)

    def on_sleep_ms(self, milliseconds: int) -> None:
        pass

    def on_start_timeout(self, milliseconds: int) -> None:
        pass

    def on_timeout_expired(self) -> bool:
        return True

    def on_spi_transfer(self, data_in: bytes) -> bytes:

        if self.with_exception:
            raise self.with_exception

        if self.waitstate:

            if self.tpm_state == MySPITcti.TPM_DID_VID_HEAD:
                b = bytearray(MySPITcti.TPM_DID_VID_0[:4])
                b[3] |= 0x01

            elif self.tpm_state == MySPITcti.TPM_DID_VID_BODY:
                b = MySPITcti.TPM_DID_VID_0[4:]

            elif self.tpm_state == MySPITcti.TPM_ACCESS_HEAD:
                b = bytearray(MySPITcti.TPM_ACCESS_0[:4])
                b[3] |= 0x01

            elif self.tpm_state == MySPITcti.TPM_ACCESS_BODY:
                b = MySPITcti.TPM_ACCESS_0[4:]

            elif self.tpm_state == MySPITcti.TPM_STS_HEAD:
                b = bytearray(MySPITcti.TPM_STS_0[:4])
                b[3] |= 0x01

            elif self.tpm_state == MySPITcti.TPM_STS_BODY:
                b = MySPITcti.TPM_STS_0[4:]

            elif self.tpm_state == MySPITcti.TPM_RID_HEAD:
                b = bytearray(MySPITcti.TPM_RID_0[:4])
                b[3] |= 0x01
            elif self.tpm_state == MySPITcti.TPM_RID_BODY:
                b = MySPITcti.TPM_RID_0[4:]
            else:
                raise RuntimeError("BAD STATE")

            self.tpm_state += 1

        else:
            if self.tpm_state == MySPITcti.TPM_DID_VID_HEAD:
                b = MySPITcti.TPM_DID_VID_0
            elif self.tpm_state == MySPITcti.TPM_ACCESS_HEAD:
                b = MySPITcti.TPM_ACCESS_0
            elif self.tpm_state == MySPITcti.TPM_STS_HEAD:
                b = MySPITcti.TPM_STS_0
            elif self.tpm_state == MySPITcti.TPM_RID_HEAD:
                b = MySPITcti.TPM_RID_0
            else:
                raise RuntimeError("BAD STATE")

            self.tpm_state += 2

        return bytes(b)

    def on_spi_acquire(self) -> None:
        pass

    def on_spi_release(self) -> None:
        pass


class MyBadSPITcti(TCTISPIHelper):
    def on_sleep_ms(self, milliseconds: int) -> None:
        pass

    def on_start_timeout(self, milliseconds: int) -> None:
        pass

    def on_timeout_expired(self) -> bool:
        return True

    def on_spi_transfer(self, data_in: bytes) -> bytes:
        pass


class MyBadSPITcti2(TCTISPIHelper):
    def on_sleep_ms(self, milliseconds: int) -> None:
        pass

    def on_start_timeout(self, milliseconds: int) -> None:
        pass

    def on_timeout_expired(self) -> bool:
        return True

    def on_spi_transfer(self, data_in: bytes) -> bytes:
        pass

    def on_spi_acquire(self) -> None:
        pass


class TestTCTI(unittest.TestCase):
    def test_spi_helper_good(self):
        MySPITcti()

    def yest_spi_helper_good_wait_state(self):
        MySPITcti(with_wait_state=True)

    def test_MyBadSPITcti(self):
        with self.assertRaises(NotImplementedError):
            MyBadSPITcti(with_wait_state=True)

    def test_MyBadSPITcti2(self):
        with self.assertRaises(NotImplementedError):
            MyBadSPITcti2(with_wait_state=True)

    def test_init_baseclase(self):
        with self.assertRaises(NotImplementedError):
            TCTISPIHelper()

    def test_init_baseclase_with_wait_state(self):
        with self.assertRaises(NotImplementedError):
            TCTISPIHelper(with_wait_state=True)

    def test_with_exception_accross_c(self):
        with self.assertRaises(RuntimeError, msg="foobar"):
            MySPITcti(with_exception=RuntimeError("foobar"))


if __name__ == "__main__":
    unittest.main()
