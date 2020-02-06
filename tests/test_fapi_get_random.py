import random
from contextlib import ExitStack

from tpm2_pytss.binding import *

from .base_esys import BaseTestFAPI


class TestGetRandom(BaseTestFAPI):
    def test_random_length(self):
        length = random.randint(8, 32)

        array = self.fapi_ctx.GetRandom(length)

        self.assertEqual(length, len(array))
