"""
Helpers for retrying a TCTI connection until it connects successfully. Useful
when the simulator startup is a bit laggy.
"""
import time
import logging
import contextlib

from ..exceptions import TPM2Error

LOGGER = logging.getLogger("tpm2_pytss.util.retry")
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
        LOGGER.debug(retry)
        if retry.tries > retry.max_tries:
            raise


def retry_tcti_loop(timeout=TCTI_RETRY_TIMEOUT, max_tries=TCTI_RETRY_TRIES):
    retry = TCTIRetry(i=-1, timeout=timeout, max_tries=max_tries)
    while not retry.success:
        retry.i += 1
        yield retry
