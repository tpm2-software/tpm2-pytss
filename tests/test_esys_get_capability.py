from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestESYS


class TestGetCapability(BaseTestESYS):
    def test_get_capability(self):
        capability = TPM2_CAP_TPM_PROPERTIES
        prop = TPM2_PT_LOCKOUT_COUNTER
        propertyCount = 1

        self.esys_ctx.GetCapability(
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, capability, prop, propertyCount,
        )
