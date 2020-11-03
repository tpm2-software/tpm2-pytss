import random
from contextlib import ExitStack

from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestFAPI


class TestGetRandom(BaseTestFAPI):
    def test_get_info(self):
        self.fapi_ctx.Provision(None, None, None)

        self.assertEqual(type(self.fapi_ctx.GetInfo()), dict)

    def test_random_length(self):
        length = random.randint(8, 32)

        self.fapi_ctx.Provision(None, None, None)

        array = self.fapi_ctx.GetRandom(length)

        value = to_bytearray(length, array)

        self.assertEqual(length, len(value))
