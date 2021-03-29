from ._libtpm2_pytss import lib, ffi


class TSS2_Exception(RuntimeError):
    def __init__(self, rc):
        errmsg = ffi.string(lib.Tss2_RC_Decode(rc)).decode()
        super(TSS2_Exception, self).__init__(f"{errmsg}")

        self.rc = rc
        self.handle = 0
        self.parameter = 0
        self.session = 0
        self.error = 0
        if self.rc & lib.TPM2_RC_FMT1:
            self._parse_fmt1()
        else:
            self.error = self.rc

    def _parse_fmt1(self):
        self.error = lib.TPM2_RC_FMT1 + (self.rc & 0x3F)

        if self.rc & lib.TPM2_RC_P:
            self.parameter = (self.rc & lib.TPM2_RC_N_MASK) >> 8
        elif self.rc & lib.TPM2_RC_S:
            self.session = ((self.rc - lib.TPM2_RC_S) & lib.TPM2_RC_N_MASK) >> 8
        else:
            self.handle = (self.rc & lib.TPM2_RC_N_MASK) >> 8
