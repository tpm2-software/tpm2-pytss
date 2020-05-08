import ctypes
from contextlib import ExitStack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from tpm2_pytss.binding import *
from tpm2_pytss.util.testing import BaseTestESYS


class TestLoadExternal(BaseTestESYS):
    def test_load_public_rsa_key(self):
        # The tpm2-tools equivalent of what this tests is attempting to do is
        # the following:

        # tpm2_loadexternal
        #    --hierarchy=o
        #    --key-algorithm=rsa
        #    --public=public_rsa_key.pem
        #    --key-context=signing_key.ctx
        #    --name=signing_key.name

        # Create the 2048 bit RSA key.
        private_rsa_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_rsa_key = private_rsa_key.public_key()

        with ExitStack() as stack:
            # Create the public part.
            in_public = TPM2B_PUBLIC(
                size=0,
                publicArea=TPMT_PUBLIC(
                    type=TPM2_ALG_RSA,  # key-algorithm=rsa
                    nameAlg=TPM2_ALG_SHA256,  # hash-algorithm = default = sha256
                    objectAttributes=ctypes.c_uint32(
                        TPMA_OBJECT_NODA
                        | TPMA_OBJECT_DECRYPT
                        | TPMA_OBJECT_SIGN_ENCRYPT
                        | TPMA_OBJECT_USERWITHAUTH
                    ).value,
                    authPolicy=TPM2B_DIGEST(size=0),
                    parameters=TPMU_PUBLIC_PARMS(
                        rsaDetail=TPMS_RSA_PARMS(
                            scheme=TPMT_RSA_SCHEME(
                                scheme=TPM2_ALG_NULL,
                                details=TPMU_ASYM_SCHEME(
                                    anySig=TPMS_SCHEME_HASH(hashAlg=TPM2_ALG_NULL,),
                                ),
                            ),
                            symmetric=TPMT_SYM_DEF_OBJECT(
                                algorithm=TPM2_ALG_NULL,
                                keyBits=TPMU_SYM_KEY_BITS(sym=0),
                                mode=TPMU_SYM_MODE(sym=TPM2_ALG_NULL),
                            ),
                            keyBits=public_rsa_key.key_size,  # Number of bits in the key 2048
                            exponent=public_rsa_key.public_numbers().e,  # exponent of the key 65537
                        ),
                    ),
                    unique=TPMU_PUBLIC_ID(
                        rsa=TPM2B_PUBLIC_KEY_RSA(
                            # public part of rsa key.
                            buffer=public_rsa_key.public_numbers().n.to_bytes(
                                public_rsa_key.key_size // 8, byteorder="big"
                            )
                        )
                    ),
                ),
            )

            in_public_ptr = stack.enter_context(in_public.ptr())
            object_handle = stack.enter_context(self.esys_ctx.flush_tr())

            self.esys_ctx.LoadExternal(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                None,
                in_public_ptr,
                TPM2_RH_OWNER,
                object_handle,
            )

            # Get name from the object_handle and compare it to the public key.
            # If there is a difference throw an exception.
