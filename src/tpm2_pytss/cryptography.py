# SPDX-License-Identifier: BSD-2

from .ESAPI import ESAPI
from .constants import ESYS_TR, TPM2_ALG, TPMA_OBJECT, TPM2_ST, TPM2_RH
from .types import (
    TPMT_RSA_DECRYPT,
    TPM2B_DATA,
    TPMT_SIG_SCHEME,
    TPMT_TK_HASHCHECK,
    TPM2B_ECC_POINT,
    TPMT_ASYM_SCHEME,
    TPMT_ECC_SCHEME,
    TPMU_SIG_SCHEME,
)
from .internal.crypto import (
    public_to_key,
    _get_curve,
    _rsa_decrypt_padding_to_scheme,
    _rsa_sign_padding_to_scheme,
    _int_to_buffer,
    _ecc_sign_algorithm_to_scheme,
    _get_digest,
)
from typing import Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    KeySerializationEncryption,
)


def _compare_schemes(
    in_scheme: Union[TPMT_RSA_DECRYPT, TPMT_SIG_SCHEME], key_scheme: TPMT_SIG_SCHEME
) -> None:
    """Compare a keys scheme and any scheme passed to sign/decrypt functions.

    Raises:
        ValueError: On any scheme mismatch.
    """
    if key_scheme.scheme == TPM2_ALG.NULL:
        return
    if in_scheme.scheme != key_scheme.scheme:
        raise ValueError(
            f"invalid scheme, scheme has {in_scheme.scheme} but key requires {key_scheme.scheme}"
        )
    if in_scheme.scheme == TPM2_ALG.RSAES:
        return
    if isinstance(in_scheme.details, TPMU_SIG_SCHEME):
        halg = in_scheme.details.any.hashAlg
    else:
        halg = in_scheme.details.anySig.hashAlg
    if halg != key_scheme.details.anySig.hashAlg:
        raise ValueError(
            f"digest algorithm mismatch, scheme has {halg} but key requires {key_scheme.details.anySig.hashAlg}"
        )


class tpm_rsa_private_key(rsa.RSAPrivateKey):
    """Interface to a TPM RSA key for use with the cryptography module.

    Args:
        ectx (ESAPI): The ESAPI instance to use.
        handle (ESYS_TR): The key handle.
        session (ESYS_TR): The session to authorize usage of the key, default is ESYS_TR.PASSWORD

    Notes:
        It is recommended to use the :func:`get_digest_algorithm`, :func:`get_decryption_padding` and :func:`get_signature_padding` methods for highest compatibility.

    Raises:
        ValueError: If the key has the restricted bit set or if the handle doesn't reference an RSA key.
    """

    def __init__(
        self, ectx: ESAPI, handle: ESYS_TR, session: ESYS_TR = ESYS_TR.PASSWORD
    ):
        self._handle = handle
        self._session = session
        self._ectx = ectx
        public, _, _ = ectx.read_public(handle)
        self._public = public.publicArea
        if self._public.type != TPM2_ALG.RSA:
            raise ValueError(
                f"invalid key type, expected {TPM2_ALG.RSA}, got {self._public.type}"
            )
        if self._public.objectAttributes & TPMA_OBJECT.RESTRICTED:
            raise ValueError(
                "TPM key does not allow generic signing and/or decryption (object attribute restricted is set)"
            )

    def decrypt(self, ciphertext: bytes, padding: padding) -> bytes:
        """Implements the decrypt interface.

        See :py:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt` for documentation.

        Notes:
            If a non-empty label is used with OAEP padding, this will fail.

        Raises:
            ValueError: if the requested padding isn't supported by the key.
        """
        if not self._public.objectAttributes & TPMA_OBJECT.DECRYPT:
            raise ValueError(
                "TPM key does not allow decryption (object attribute decrypt is not set)"
            )
        scheme = TPMT_RSA_DECRYPT()
        _rsa_decrypt_padding_to_scheme(padding, scheme)
        _compare_schemes(scheme, self._public.parameters.rsaDetail.scheme)
        data2b = self._ectx.rsa_decrypt(
            self._handle, ciphertext, scheme, TPM2B_DATA(), session1=self._session
        )
        return bytes(data2b)

    def public_key(self) -> rsa.RSAPublicKey:
        """Get the public key.

        Returns: the public part of the RSA key as a :py:class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
        """
        return public_to_key(self._public)

    @property
    def key_size(self) -> int:
        """The RSA key size"""
        return self._public.parameters.rsaDetail.keyBits

    def get_digest_algorithm(self) -> hashes.HashAlgorithm:
        """Get an usable digest algorithm for use with the key.

        If any scheme with a specified digest algorithm is specified return that algorithm.
        Otherwise the name digest algorithm is returned.

        The returned digest algorithm can be used with different cryptography functions.

        Returns:
            The digest algorithm as a :py:class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` subclass.

        Raises:
            ValueError: If the digest algorithm is not supported.
        """
        if self._public.parameters.rsaDetail.scheme.scheme in (
            TPM2_ALG.RSASSA,
            TPM2_ALG.RSAPSS,
            TPM2_ALG.OAEP,
        ):
            tpm_alg = self._public.parameters.rsaDetail.scheme.details.anySig.hashAlg
        else:
            tpm_alg = self._public.nameAlg
        halg = _get_digest(tpm_alg)
        if halg is None:
            raise ValueError(f"unsupported digest algorithm {tpm_alg}")
        return halg

    def get_decryption_padding(self) -> padding.AsymmetricPadding:
        """Get a padding configuration for use with the decrypt method.

        If the key has a scheme specified, use that scheme.
        Otherwise, use OAEP as the default.

        Returns:
            An instance of :py:class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        Raises:
            ValueError: If the either the scheme or digest algorithm is unsupported.
        """
        if self._public.parameters.asymDetail.scheme.scheme == TPM2_ALG.NULL:
            scheme = TPMT_ASYM_SCHEME(scheme=TPM2_ALG.OAEP)
            scheme.details.anySig.hashAlg = self._public.nameAlg
        else:
            scheme = self._public.parameters.asymDetail.scheme
        if scheme.scheme == TPM2_ALG.OAEP:
            algorithm = self.get_digest_algorithm()
            decrypt_padding = padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm()),
                algorithm=algorithm(),
                label=b"",
            )
        elif scheme.scheme == TPM2_ALG.RSAES:
            decrypt_padding = padding.PKCS1v15()
        else:
            raise ValueError(f"unsupported decryption scheme {scheme.scheme}")
        return decrypt_padding

    def get_signature_padding(self) -> padding.AsymmetricPadding:
        """Get a padding configuration for use with the sign method.

        If the key has a scheme specified, use that scheme.
        Otherwise, use PSS as the default.

        Returns:
          An instance of :py:class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`.

        Raises: ValueError if the either the scheme or digest algorithm is unsupported.
        """
        if self._public.parameters.asymDetail.scheme.scheme == TPM2_ALG.NULL:
            scheme = TPMT_ASYM_SCHEME(scheme=TPM2_ALG.RSAPSS)
            scheme.details.anySig.hashAlg = self._public.nameAlg
        else:
            scheme = self._public.parameters.asymDetail.scheme
        if scheme.scheme == TPM2_ALG.RSAPSS:
            algorithm = self.get_digest_algorithm()
            sign_padding = padding.PSS(
                mgf=padding.MGF1(algorithm=algorithm()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            )
        elif scheme.scheme == TPM2_ALG.RSASSA:
            sign_padding = padding.PKCS1v15()
        else:
            raise ValueError(f"unsupported signature scheme {scheme.scheme}")
        return sign_padding

    def sign(
        self,
        data: bytes,
        padding: padding,
        algorithm: Union[hashes.HashAlgorithm, Prehashed],
    ) -> bytes:
        """Implements the sign interface.

        See :py:meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign` for documentationen.

        Notes:
            For PSS padding, the salt length should be set to the length of the digest as that is the only setup the TPM uses.

        Raises:
            ValueError: If the requested padding isn't supported by the key or the sign_encrypt bit isn't set.
        """
        if not self._public.objectAttributes & TPMA_OBJECT.SIGN_ENCRYPT:
            raise ValueError(
                "TPM key does not allow signing (object attribute sign_encrypt is not set)"
            )
        if isinstance(algorithm, Prehashed):
            raise ValueError("Prehashed data is not supported")
        scheme = TPMT_SIG_SCHEME()
        _rsa_sign_padding_to_scheme(padding, type(algorithm), scheme)
        _compare_schemes(scheme, self._public.parameters.rsaDetail.scheme)
        h = hashes.Hash(algorithm)
        h.update(data)
        digest = h.finalize()
        validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.NULL)
        tpm_sig = self._ectx.sign(
            self._handle, digest, scheme, validation, session1=self._session
        )
        return bytes(tpm_sig)

    def private_numbers(self) -> None:
        """Always raises a NotImplementedError."""
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> None:
        """Always raises a NotImplementedError."""
        raise NotImplementedError()


class tpm_ecc_private_key(ec.EllipticCurvePrivateKey):
    """Interface to a TPM ECC key for use with the cryptography module.

    Args:
        ectx (ESAPI): The ESAPI instance to use.
        handle (ESYS_TR): The key handle.
        session (ESYS_TR): The session to authorize usage of the key, default is ESYS_TR.PASSWORD

    Notes:
        It is recommended to use the :func:`get_digest_algorithm` and :func:`get_signature_algorithm` methods for highest compatibility.

    Raises:
        ValueError: If the key has the restricted bit set, the curve isn't supported or if the handle doesn't reference an ECC key.
    """

    def __init__(
        self, ectx: ESAPI, handle: ESYS_TR, session: ESYS_TR = ESYS_TR.PASSWORD
    ):
        self._handle = handle
        self._session = session
        self._ectx = ectx
        public, _, _ = ectx.read_public(handle)
        self._public = public.publicArea
        if self._public.type != TPM2_ALG.ECC:
            raise ValueError(
                f"invalid key type, expected {TPM2_ALG.ECC}, got {self._public.type}"
            )
        if self._public.objectAttributes & TPMA_OBJECT.RESTRICTED:
            raise ValueError(
                "TPM key does not allow generic signing and/or decryption (object attribute restricted is set)"
            )
        cid = _get_curve(self._public.parameters.eccDetail.curveID)
        if cid is None:
            raise ValueError(
                f"unsupported curve {self._public.parameters.eccDetail.curveID}"
            )
        self._curve = cid

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        """Implements the exchange interface.

        See :py:meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange` for documentationen.

        Raises:
            ValueError: If the curves does not match or the decrypt bit isn't set.
        """
        if not self._public.objectAttributes & TPMA_OBJECT.DECRYPT:
            raise ValueError(
                "TPM key does not allow ECDH key exchange (object attribute decrypt is not set)"
            )
        if type(peer_public_key.curve) != type(self.curve):
            raise ValueError(
                f"curve mismatch for peer key, got {peer_public_key.curve.name}, expected {self.curve.name}"
            )
        scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDH)
        _compare_schemes(scheme, self._public.parameters.eccDetail.scheme)
        in_point = TPM2B_ECC_POINT()
        nums = peer_public_key.public_numbers()
        _int_to_buffer(nums.x, in_point.point.x)
        _int_to_buffer(nums.y, in_point.point.y)

        out_point = self._ectx.ecdh_zgen(self._handle, in_point, session1=self._session)
        return bytes(out_point.point.x)

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get the public key.

        Returns: the public part of the ECC key as a :py:class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        """
        return public_to_key(self._public)

    def get_digest_algorithm(self) -> hashes.HashAlgorithm:
        """Get an usable digest algorithm for use with the key.

        If any scheme with a specified digest algorithm is specified return that algorithm.
        Otherwise the name digest algorithm is returned.

        The returned digest algorithm can be used with different cryptography functions.

        Returns:
            The digest algorithm as a :py:class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` subclass.

        Raises:
            ValueError: If the digest algorithm is not supported.
        """
        if self._public.parameters.eccDetail.scheme.scheme == TPM2_ALG.ECDSA:
            tpm_alg = self._public.parameters.eccDetail.scheme.details.anySig.hashAlg
        else:
            tpm_alg = self._public.nameAlg
        halg = _get_digest(tpm_alg)
        if halg is None:
            raise ValueError(f"unsupported digest algorithm {tpm_alg}")
        return halg

    def get_signature_algorithm(self) -> ec.EllipticCurveSignatureAlgorithm:
        """Get a padding configuration for use with the sign method.

        If the key has a scheme specified, use that scheme.
        Otherwise, use ECDSA as the default

        Returns: an instance of :py:class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurveSignatureAlgorithm`

        Raises:
            ValueError: If the either the scheme or digest algorithm is unsupported.
        """
        if self._public.parameters.eccDetail.scheme.scheme == TPM2_ALG.NULL:
            scheme = TPMT_ECC_SCHEME(scheme=TPM2_ALG.ECDSA)
            scheme.details.anySig.hashAlg = self._public.nameAlg
        else:
            scheme = self._public.parameters.eccDetail.scheme
        if scheme.scheme == TPM2_ALG.ECDSA:
            algorithm = self.get_digest_algorithm()
            sig_alg = ec.ECDSA(algorithm())
        else:
            raise ValueError(f"unsupported signature scheme {scheme.scheme}")
        return sig_alg

    def sign(
        self, data: bytes, signature_algorithm: ec.EllipticCurveSignatureAlgorithm
    ) -> bytes:
        """Implements the sign interface.

        See :py:meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign`: for documentation.

        Raises:
            ValueError: if the requested signature algorithm isn't supported by the key or the sign_encrypt bit isn't set.
        """
        if not self._public.objectAttributes & TPMA_OBJECT.SIGN_ENCRYPT:
            raise ValueError(
                "TPM key does not allow signing (object attribute sign_encrypt is not set)"
            )
        algorithm = signature_algorithm.algorithm
        if isinstance(algorithm, Prehashed):
            raise ValueError("Prehashed data is not supported")
        scheme = TPMT_SIG_SCHEME()
        _ecc_sign_algorithm_to_scheme(signature_algorithm, scheme)
        _compare_schemes(scheme, self._public.parameters.eccDetail.scheme)
        h = hashes.Hash(algorithm)
        h.update(data)
        digest = h.finalize()
        validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.NULL)
        tpm_sig = self._ectx.sign(
            self._handle, digest, scheme, validation, session1=self._session
        )
        return bytes(tpm_sig)

    @property
    def curve(self) -> ec.EllipticCurve:
        """The ECC curve."""
        return self._curve()

    @property
    def key_size(self) -> int:
        """The ECC key size."""
        return self.public_key().key_size

    def private_numbers(self) -> None:
        """Always raises a NotImplementedError."""
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> None:
        """Always raises a NotImplementedError."""
        raise NotImplementedError()
