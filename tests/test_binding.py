import unittest

from tpm2_pytss.binding import *


class TestBinding(unittest.TestCase):
    def test_set_array(self):
        # TPML_PCR_SELECTION
        sel = TPMS_PCR_SELECTION(
            hash=TPM2_ALG_SHA256, sizeofSelect=3, pcrSelect=(0, 0, 255)
        )

        TPMS_PCR_SELECTION(hash=TPM2_ALG_SHA256, sizeofSelect=3, pcrSelect=(0, 0, 255))

        sels = TPML_PCR_SELECTION(count=1, pcrSelections=(sel,))

        # TPML_DIGEST
        dig1 = TPM2B_DIGEST(size=32, buffer=bytes(range(32)))
        dig2 = TPM2B_DIGEST(size=32, buffer=bytes(range(1, 33)))

        digs = TPML_DIGEST(count=2, digests=[dig1, dig2,])
