import os
import tempfile
import unittest
import contextlib

from tpm2_pytss import tcti
from tpm2_pytss.esys import ESYS
from tpm2_pytss.fapi import FAPI, FAPIConfig
from tpm2_pytss.util.simulator import SimulatorTest

ENV_TCTI = "PYESYS_TCTI"
ENV_TCTI_DEFAULT = "mssim"
ENV_TCTI_CONFIG = "PYESYS_TCTI_CONFIG"
ENV_TCTI_CONFIG_DEFAULT = None


class BaseTestESYS(SimulatorTest, unittest.TestCase):
    """
    ESYS tests should subclass from this
    """

    def setUp(self):
        super().setUp()
        self.esys = ESYS()
        self.tcti = tcti.TCTI.load(os.getenv(ENV_TCTI, default=ENV_TCTI_DEFAULT))
        self.tcti_config = os.getenv(
            ENV_TCTI_CONFIG, default="port=%d" % (self.simulator.port)
        )
        # Create a context stack
        self.ctx_stack = contextlib.ExitStack().__enter__()
        # Enter the contexts
        self.tcti_ctx = self.ctx_stack.enter_context(self.tcti(config=self.tcti_config))
        self.esys_ctx = self.ctx_stack.enter_context(self.esys(self.tcti_ctx))
        # Call Startup and clear the TPM
        self.esys_ctx.Startup(self.esys_ctx.TPM2_SU_CLEAR)
        # Set the timeout to blocking
        self.esys_ctx.SetTimeout(self.esys_ctx.TSS2_TCTI_TIMEOUT_BLOCK)

    def tearDown(self):
        super().tearDown()
        self.ctx_stack.__exit__(None, None, None)


class BaseTestFAPI(SimulatorTest, unittest.TestCase):
    """
    FAPI tests should subclass from this
    """

    def setUp(self):
        super().setUp()
        # Create a context stack
        self.ctx_stack = contextlib.ExitStack().__enter__()
        # Create temporary directories
        self.user_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
        self.log_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
        self.system_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
        # Create the FAPI object
        self.fapi = FAPI(
            FAPIConfig.default()._replace(
                user_dir=self.user_dir,
                system_dir=self.system_dir,
                log_dir=self.log_dir,
                tcti="mssim:port=%d" % (self.simulator.port,),
            )
        )
        # Enter the contexts
        self.fapi_ctx = self.ctx_stack.enter_context(self.fapi)

    def tearDown(self):
        super().tearDown()
        self.ctx_stack.__exit__(None, None, None)
