import _cffi_backend

# check that we can load the C bindings,
# if we can't, provide a better message.
try:
    from ._libtpm2_pytss import lib
except ImportError as e:
    parts = e.msg.split(": ", 2)
    if len(parts) != 3:
        raise e
    path, error, symbol = parts
    if error != "undefined symbol":
        raise e
    raise ImportError(
        f"failed to load tpm2-tss bindigs in {path} due to missing symbol {symbol}, "
        + "ensure that you are using the same libraries the python module was built against."
    )

from .ESAPI import ESAPI

try:
    from .FAPI import *
except NotImplementedError:
    # Built on a system lacking FAPI, ignore
    pass
try:
    from .policy import *
except NotImplementedError:
    # Built on a system lacking libpolicy, ignore
    pass
from .TCTILdr import *
from .TCTI import TCTI, PyTCTI, PollData
from .types import *
from .constants import *
from .TSS2_Exception import TSS2_Exception
