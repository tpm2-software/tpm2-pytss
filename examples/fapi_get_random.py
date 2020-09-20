import sys
import random
import tempfile
import contextlib

from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.binding import *
from tpm2_pytss.util.simulator import Simulator


def main():
    # Usage information
    if len(sys.argv) != 2:
        print(f"Ouput N random bytes to stdout", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"Usage: {sys.argv[0]} length(between 8 and 32)", file=sys.stderr)
        sys.exit(1)
    # Number of random bytes to get (between 8 and 32)
    length = int(sys.argv[1])
    # Input validation
    if length < 8 or length > 32:
        raise ValueError("length must be between 8 and 32")
    # Create a context stack
    with contextlib.ExitStack() as ctx_stack:
        # Create a simulator
        simulator = ctx_stack.enter_context(Simulator())
        # Create temporary directories to separate this example's state
        user_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        log_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        system_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        # Create the FAPI object
        fapi = FAPI(
            FAPIDefaultConfig._replace(
                user_dir=user_dir,
                system_dir=system_dir,
                log_dir=log_dir,
                tcti="mssim:port=%d" % (simulator.port,),
                tcti_retry=100,
                ek_cert_less=1,
            )
        )
        # Enter the context, create TCTI connection
        fapi_ctx = ctx_stack.enter_context(fapi)
        # Call Fapi_Provision
        fapi_ctx.Provision(None, None, None)
        # Create a pointer to the byte array we'll get back from GetRandom
        array = ctx_stack.enter_context(UINT8_PTR_PTR())
        # Call GetRandom and convert the resulting array to a Python bytearray
        value = to_bytearray(length, fapi_ctx.GetRandom(length, array))
        # Ensure we got the correct number of bytes
        if length != len(value):
            raise AssertionError("Requested %d bytes, got %d" % (length, len(value)))
        # Print bytes to stdout
        sys.stdout.buffer.write(value)


if __name__ == "__main__":
    main()
