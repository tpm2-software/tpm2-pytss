import random
import tempfile
import contextlib

from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.binding import *
from tpm2_pytss.util.simulator import Simulator


def main():
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
        # Number of random bytes to get
        length = random.randint(8, 32)
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
        print("GetRandom(%d):" % (length,), value)


if __name__ == "__main__":
    main()
