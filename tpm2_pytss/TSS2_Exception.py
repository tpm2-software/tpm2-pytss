from ._libtpm2_pytss import lib, ffi
from .types import TPM2_RC


class TSS2_Exception(RuntimeError):
    def __init__(self, rc):
        errmsg = ffi.string(lib.Tss2_RC_Decode(rc)).decode()
        super(TSS2_Exception, self).__init__(f"{errmsg}")

        self.rc = rc
        self.handle = 0
        self.parameter = 0
        self.session = 0
        self.error = 0
        if self.rc & TPM2_RC.FMT1:
            self._parse_fmt1()
        else:
            self.error = self.rc

    def _parse_fmt1(self):
        self.error = TPM2_RC.FMT1 + (self.rc & 0x3F)

        if self.rc & TPM2_RC.P:
            self.parameter = (self.rc & TPM2_RC.N_MASK) >> 8
        elif self.rc & TPM2_RC.S:
            self.session = ((self.rc - TPM2_RC.S) & TPM2_RC.N_MASK) >> 8
        else:
            self.handle = (self.rc & TPM2_RC.N_MASK) >> 8
