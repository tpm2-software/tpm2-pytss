#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2

from .TSS2_BaseTest import TSS2_EsapiTest
from tpm2_pytss.constants import TPMA_OBJECT, TPM2_ECC, TPM2_ALG
from tpm2_pytss.types import TPM2B_PUBLIC
from tpm2_pytss.cryptography import tpm_rsa_private_key, tpm_ecc_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, PKCS1v15, PSS
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography import x509
import datetime


rsa_template = TPM2B_PUBLIC.parse(
    "rsa2048",
    objectAttributes=TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.SIGN_ENCRYPT
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN
    | TPMA_OBJECT.USERWITHAUTH,
)

ecc_template = TPM2B_PUBLIC.parse(
    "ecc256",
    objectAttributes=TPMA_OBJECT.DECRYPT
    | TPMA_OBJECT.SIGN_ENCRYPT
    | TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN
    | TPMA_OBJECT.USERWITHAUTH,
)


class TestCryptography(TSS2_EsapiTest):
    def test_rsa_key(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        self.assertEqual(privkey.key_size, 2048)

        with self.assertRaises(NotImplementedError) as e:
            privkey.private_numbers()

        with self.assertRaises(NotImplementedError) as e:
            privkey.private_bytes(encoding=None, format=None, encryption_algorithm=None)

    def test_rsa_decrypt_oaep(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        padding = privkey.get_decryption_padding()
        encrypted_data = pubkey.encrypt(b"falafel", padding)

        decrypted_data = privkey.decrypt(encrypted_data, padding)
        self.assertEqual(decrypted_data, b"falafel")

    def test_rsa_decrypt_pkcs1v15(self):
        rsaes = TPM2B_PUBLIC(rsa_template)
        rsaes.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSAES
        rsaes.publicArea.objectAttributes ^= TPMA_OBJECT.SIGN_ENCRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsaes
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        padding = privkey.get_decryption_padding()
        encrypted_data = pubkey.encrypt(b"falafel", padding)

        decrypted_data = privkey.decrypt(encrypted_data, padding)
        self.assertEqual(decrypted_data, b"falafel")

    def test_rsa_key_bad_type(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        with self.assertRaises(ValueError) as e:
            tpm_rsa_private_key(self.ectx, handle)
        self.assertEqual(str(e.exception), "invalid key type, expected rsa, got ecc")

    def test_rsa_key_restricted(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public="rsa2048"
        )
        with self.assertRaises(ValueError) as e:
            tpm_rsa_private_key(self.ectx, handle)
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow generic signing and/or decryption (object attribute restricted is set)",
        )

    def test_rsa_sign_pss(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        padding = privkey.get_signature_padding()
        halg = privkey.get_digest_algorithm()

        sig = privkey.sign(b"falafel", padding, halg())
        pubkey.verify(sig, b"falafel", padding, halg())

    def test_rsa_sign_pkcs1v15(self):
        rsassa = TPM2B_PUBLIC(rsa_template)
        rsassa.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSASSA
        rsassa.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = (
            TPM2_ALG.SHA384
        )
        rsassa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT

        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsassa
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        padding = privkey.get_signature_padding()
        halg = privkey.get_digest_algorithm()

        sig = privkey.sign(b"falafel", padding, halg())
        pubkey.verify(sig, b"falafel", padding, halg())

    def test_rsa_no_decrypt(self):
        rsa_no_decrypt = TPM2B_PUBLIC(rsa_template)
        rsa_no_decrypt.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_no_decrypt
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = PKCS1v15()
        with self.assertRaises(ValueError) as e:
            privkey.decrypt(b"falafel", padding)
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow decryption (object attribute decrypt is not set)",
        )

    def test_rsa_no_sign(self):
        rsa_no_sign = TPM2B_PUBLIC(rsa_template)
        rsa_no_sign.publicArea.objectAttributes ^= TPMA_OBJECT.SIGN_ENCRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_no_sign
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = PKCS1v15()
        halg = privkey.get_digest_algorithm()
        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", padding, halg())
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow signing (object attribute sign_encrypt is not set)",
        )

    def test_rsa_prehashed(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = PKCS1v15()
        halg = privkey.get_digest_algorithm()
        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", padding, Prehashed(halg()))
        self.assertEqual(str(e.exception), "Prehashed data is not supported")

    def test_rsa_unsupported_sig_scheme(self):
        rsaes = TPM2B_PUBLIC(rsa_template)
        rsaes.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSAES
        rsaes.publicArea.objectAttributes ^= TPMA_OBJECT.SIGN_ENCRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsaes
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        with self.assertRaises(ValueError) as e:
            privkey.get_signature_padding()
        self.assertEqual(str(e.exception), "unsupported signature scheme rsaes")

    def test_rsa_unsupported_decrypt_scheme(self):
        rsassa = TPM2B_PUBLIC(rsa_template)
        rsassa.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSASSA
        rsassa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsassa
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        with self.assertRaises(ValueError) as e:
            privkey.get_decryption_padding()
        self.assertEqual(str(e.exception), "unsupported decryption scheme rsassa")

    def test_ecc_key(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)
        self.assertEqual(privkey.key_size, 256)
        self.assertIsInstance(privkey.curve, ec.SECP256R1)

        with self.assertRaises(NotImplementedError) as e:
            privkey.private_numbers()

        with self.assertRaises(NotImplementedError) as e:
            privkey.private_bytes(encoding=None, format=None, encryption_algorithm=None)

    def test_ecc_key_bad_type(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        with self.assertRaises(ValueError) as e:
            tpm_ecc_private_key(self.ectx, handle)
        self.assertEqual(str(e.exception), "invalid key type, expected ecc, got rsa")

    def test_ecc_key_restricted(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public="ecc256"
        )
        with self.assertRaises(ValueError) as e:
            tpm_ecc_private_key(self.ectx, handle)
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow generic signing and/or decryption (object attribute restricted is set)",
        )

    def test_ecc_exchange(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        peer_key = ec.generate_private_key(privkey.curve)
        peer_public_key = peer_key.public_key()

        tpm_shared_key = privkey.exchange(ec.ECDH(), peer_public_key)
        pyca_shared_key = peer_key.exchange(ec.ECDH(), privkey.public_key())
        self.assertEqual(tpm_shared_key, pyca_shared_key)

    def test_ecc_sign(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        sigalg = privkey.get_signature_algorithm()
        sig = privkey.sign(b"falafel", sigalg)

        pubkey.verify(sig, b"falafel", sigalg)

    def test_ecc_sign_with_scheme(self):
        ecc_ecdsa = TPM2B_PUBLIC(ecc_template)
        ecc_ecdsa.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDSA
        ecc_ecdsa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_ecdsa
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        sigalg = privkey.get_signature_algorithm()
        sig = privkey.sign(b"falafel", sigalg)

        pubkey.verify(sig, b"falafel", sigalg)

    def test_ecc_no_decrypt(self):
        ecc_no_decrypt = TPM2B_PUBLIC(ecc_template)
        ecc_no_decrypt.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_no_decrypt
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        peer_key = ec.generate_private_key(privkey.curve)
        peer_public_key = peer_key.public_key()

        with self.assertRaises(ValueError) as e:
            privkey.exchange(ec.ECDH(), peer_public_key)
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow ECDH key exchange (object attribute decrypt is not set)",
        )

    def test_ecc_different_curves(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        peer_key = ec.generate_private_key(ec.SECP192R1())
        peer_public_key = peer_key.public_key()

        with self.assertRaises(ValueError) as e:
            privkey.exchange(ec.ECDH(), peer_public_key)
        self.assertEqual(
            str(e.exception),
            "curve mismatch for peer key, got secp192r1, expected secp256r1",
        )

    def test_ecc_no_sign(self):
        ecc_no_sign = TPM2B_PUBLIC(ecc_template)
        ecc_no_sign.publicArea.objectAttributes ^= TPMA_OBJECT.SIGN_ENCRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_no_sign
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        halg = privkey.get_digest_algorithm()
        sigalg = ec.ECDSA(halg())
        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", sigalg)
        self.assertEqual(
            str(e.exception),
            "TPM key does not allow signing (object attribute sign_encrypt is not set)",
        )

    def test_ecc_prehashed(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        halg = privkey.get_digest_algorithm()
        sigalg = ec.ECDSA(Prehashed(halg()))
        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", sigalg)
        self.assertEqual(str(e.exception), "Prehashed data is not supported")

    def test_ecc_unsupported_curve(self):
        ecc_brainpool = TPM2B_PUBLIC(ecc_template)
        ecc_brainpool.publicArea.parameters.eccDetail.curveID = TPM2_ECC.BN_P256
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_brainpool
        )

        with self.assertRaises(ValueError) as e:
            tpm_ecc_private_key(self.ectx, handle)
        self.assertEqual(str(e.exception), "unsupported curve bn_p256")

    def test_ecc_unsupported_scheme(self):
        ecc_ecdaa = TPM2B_PUBLIC(ecc_template)
        ecc_ecdaa.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDAA
        ecc_ecdaa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT

        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_ecdaa
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        with self.assertRaises(ValueError) as e:
            privkey.get_signature_algorithm()
        self.assertEqual(str(e.exception), "unsupported signature scheme ecdaa")

    def test_scheme_mismatch(self):
        rsassa = TPM2B_PUBLIC(rsa_template)
        rsassa.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSASSA
        rsassa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT

        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsassa
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = PSS(
            mgf=MGF1(algorithm=hashes.SHA256()), salt_length=PSS.DIGEST_LENGTH
        )

        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", padding, hashes.SHA256())
        self.assertEqual(
            str(e.exception),
            "invalid scheme, scheme has rsapss but key requires rsassa",
        )

    def test_scheme_digest_mismatch(self):
        rsassa = TPM2B_PUBLIC(rsa_template)
        rsassa.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.RSASSA
        rsassa.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = (
            TPM2_ALG.SHA1
        )
        rsassa.publicArea.objectAttributes ^= TPMA_OBJECT.DECRYPT

        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsassa
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = PKCS1v15()

        with self.assertRaises(ValueError) as e:
            privkey.sign(b"falafel", padding, hashes.SHA256())
        self.assertEqual(
            str(e.exception),
            "digest algorithm mismatch, scheme has sha256 but key requires sha",
        )

    def test_scheme_digest_mismatch_oaep(self):
        rsa_oaep = TPM2B_PUBLIC(rsa_template)
        rsa_oaep.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG.OAEP
        rsa_oaep.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = (
            TPM2_ALG.SHA256
        )
        rsa_oaep.publicArea.objectAttributes ^= TPMA_OBJECT.SIGN_ENCRYPT
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_oaep
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        padding = OAEP(
            mgf=MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA384(), label=b""
        )

        with self.assertRaises(ValueError) as e:
            privkey.decrypt(b"falafel", padding)
        self.assertEqual(
            str(e.exception),
            "digest algorithm mismatch, scheme has sha384 but key requires sha256",
        )

    def test_cert_builder_rsa(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        builder = builder.serial_number(x509.random_serial_number())
        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + one_day)
        builder = builder.public_key(pubkey)

        halg = privkey.get_digest_algorithm()
        cert = builder.sign(privkey, algorithm=halg())
        cert.verify_directly_issued_by(cert)

    def test_csr_builder_rsa(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=rsa_template
        )
        privkey = tpm_rsa_private_key(self.ectx, handle)

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        halg = privkey.get_digest_algorithm()
        csr = builder.sign(privkey, algorithm=halg())
        self.assertEqual(csr.is_signature_valid, True)

    def test_cert_builder_ecc(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)
        pubkey = privkey.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        builder = builder.serial_number(x509.random_serial_number())
        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + one_day)
        builder = builder.public_key(pubkey)

        halg = privkey.get_digest_algorithm()
        cert = builder.sign(privkey, algorithm=halg())
        cert.verify_directly_issued_by(cert)

    def test_csr_builder_ecc(self):
        handle, _, _, _, _ = self.ectx.create_primary(
            in_sensitive=None, in_public=ecc_template
        )
        privkey = tpm_ecc_private_key(self.ectx, handle)

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "falafel"),])
        )
        halg = privkey.get_digest_algorithm()
        csr = builder.sign(privkey, algorithm=halg())
        self.assertEqual(csr.is_signature_valid, True)
