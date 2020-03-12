import random
from contextlib import ExitStack

from tpm2_pytss.binding import *

from .base_esys import BaseTestFAPI


class TestGetRandom(BaseTestFAPI):
    def test_random_length(self):
        length = random.randint(8, 32)

        self.fapi_ctx.Provision(None, None, None)

        array = UINT8_PTR_PTR()

        with array:
            self.fapi_ctx.GetRandom(length, array)

            value = to_bytearray(length, array.value)

            self.assertEqual(length, len(value))
