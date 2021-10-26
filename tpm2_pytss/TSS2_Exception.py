from ._libtpm2_pytss import lib, ffi
from typing import Union


class TSS2_Exception(RuntimeError):
    """TSS2_Exception represents an error returned by the TSS APIs."""

    # prevent cirular dependency and don't use the types directly here.
    def __init__(self, rc: Union["TSS2_RC", "TPM2_RC", int]):
        if isinstance(rc, int):
            # defer this to avoid circular dep.
            from .constants import TSS2_RC

            rc = TSS2_RC(rc)
        errmsg = ffi.string(lib.Tss2_RC_Decode(rc)).decode()
        super(TSS2_Exception, self).__init__(f"{errmsg}")

        self._rc = rc
        self._handle = 0
        self._parameter = 0
        self._session = 0
        self._error = 0
        if self._rc & lib.TPM2_RC_FMT1:
            self._parse_fmt1()
        else:
            self._error = self._rc

    def _parse_fmt1(self):
        self._error = lib.TPM2_RC_FMT1 + (self.rc & 0x3F)

        if self.rc & lib.TPM2_RC_P:
            self._parameter = (self.rc & lib.TPM2_RC_N_MASK) >> 8
        elif self.rc & lib.TPM2_RC_S:
            self._session = ((self.rc - lib.TPM2_RC_S) & lib.TPM2_RC_N_MASK) >> 8
        else:
            self._handle = (self.rc & lib.TPM2_RC_N_MASK) >> 8

    @property
    def rc(self):
        """int: The return code from the API call."""
        return self._rc

    @property
    def handle(self):
        """int: The handle related to the error, 0 if not related to any handle."""
        return self._handle

    @property
    def parameter(self):
        """int: The parameter related to the error, 0 if not related to any parameter."""
        return self._parameter

    @property
    def session(self):
        """int: The session related to the error, 0 if not related to any session."""
        return self._session

    @property
    def error(self):
        """int: The error with handle, parameter and session stripped."""
        return self._error

    @property
    def fmt1(self):
        """bool: True if the error is related to a handle, parameter or session """
        return bool(self._rc & lib.TPM2_RC_FMT1)
