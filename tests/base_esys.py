import os
import time
import tempfile
import unittest
import contextlib

from tpm2_pytss import tcti
from tpm2_pytss.esys import ESYS
from tpm2_pytss.fapi import FAPI, FAPIConfig
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.util.simulator import SimulatorTest

ENV_TCTI = "PYESYS_TCTI"
ENV_TCTI_DEFAULT = "mssim"
ENV_TCTI_CONFIG = "PYESYS_TCTI_CONFIG"
ENV_TCTI_CONFIG_DEFAULT = None

TCTI_RETRY_TRIES = 50
TCTI_RETRY_TIMEOUT = 0.5


class TCTIRetry:
    def __init__(
        self, i=0, timeout=TCTI_RETRY_TIMEOUT, tries=0, max_tries=TCTI_RETRY_TRIES
    ):
        self.i = i
        self.timeout = timeout
        self.tries = tries
        self.max_tries = max_tries
        self.success = False

    def __str__(self):
        return "%s(i=%d, timeout=%f, tries=%d, max_tries=%d, success=%s)" % (
            self.__class__.__qualname__,
            self.i,
            self.timeout,
            self.tries,
            self.max_tries,
            self.success,
        )


@contextlib.contextmanager
def retry_tcti_catch(retry):
    retry.success = True
    try:
        yield retry
    except TPM2Error as error:
        retry.success = False
        if not "tcti:IO failure" in str(error):
            raise
        time.sleep(retry.timeout)
        retry.tries += 1
        retry.timeout *= 1.08
        print(retry)
        if retry.tries > retry.max_tries:
            raise


def retry_tcti_loop(timeout=TCTI_RETRY_TIMEOUT, max_tries=TCTI_RETRY_TRIES):
    retry = TCTIRetry(i=-1, timeout=timeout, max_tries=max_tries)
    while not retry.success:
        retry.i += 1
        yield retry


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
        for retry in retry_tcti_loop():
            with retry_tcti_catch(retry):
                self.tcti_ctx = self.ctx_stack.enter_context(
                    self.tcti(config=self.tcti_config)
                )
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
        for retry in retry_tcti_loop():
            with retry_tcti_catch(retry):
                self.fapi_ctx = self.ctx_stack.enter_context(self.fapi)

    def tearDown(self):
        super().tearDown()
        self.ctx_stack.__exit__(None, None, None)
