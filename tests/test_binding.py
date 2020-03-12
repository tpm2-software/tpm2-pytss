import unittest

from tpm2_pytss.binding import *


class TestBinding(unittest.TestCase):
    def test_set_array(self):
        sel = TPMS_PCR_SELECTION(
            hash=TPM2_ALG_SHA256, sizeofSelect=3, pcrSelect=(0, 0, 255)
        )

        TPMS_PCR_SELECTION(hash=TPM2_ALG_SHA256, sizeofSelect=3, pcrSelect=(0, 0, 255))

        sels = TPML_PCR_SELECTION(count=1, pcrSelections=(sel,))
