from .types import TPM2_RC


class TSS2_Exception(RuntimeError):
    def __init__(self, rc):
        super(TSS2_Exception, self).__init__(f"TSS2 Library call failed with: 0x{rc:X}")
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
