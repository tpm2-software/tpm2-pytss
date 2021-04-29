"""
SPDX-License-Identifier: BSD-2
"""

from math import ceil
from ._libtpm2_pytss import lib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.backends import default_backend

_curvetable = (
    (lib.TPM2_ECC_NIST_P192, ec.SECP192R1),
    (lib.TPM2_ECC_NIST_P224, ec.SECP224R1),
    (lib.TPM2_ECC_NIST_P256, ec.SECP256R1),
    (lib.TPM2_ECC_NIST_P384, ec.SECP384R1),
    (lib.TPM2_ECC_NIST_P521, ec.SECP521R1),
    (lib.TPM2_ECC_BN_P256, None),
    (lib.TPM2_ECC_BN_P638, None),
    (lib.TPM2_ECC_SM2_P256, None),
)

_digesttable = (
    (lib.TPM2_ALG_SHA1, hashes.SHA1),
    (lib.TPM2_ALG_SHA256, hashes.SHA256),
    (lib.TPM2_ALG_SHA384, hashes.SHA384),
    (lib.TPM2_ALG_SHA512, hashes.SHA512),
    (lib.TPM2_ALG_SHA3_256, hashes.SHA3_256),
    (lib.TPM2_ALG_SHA3_384, hashes.SHA3_384),
    (lib.TPM2_ALG_SHA3_512, hashes.SHA3_512),
)


def _get_curveid(curve):
    for (algid, c) in _curvetable:
        if isinstance(curve, c):
            return algid
    return None


def _get_curve(curveid):
    for (algid, c) in _curvetable:
        if algid == curveid:
            return c
    return None


def _get_digest(digestid):
    for (algid, d) in _digesttable:
        if algid == digestid:
            return d
    return None


def _int_to_buffer(i, b):
    s = ceil(i.bit_length() / 8)
    b.buffer = i.to_bytes(length=s, byteorder="big")


def public_from_pem(data, obj):
    key = load_pem_public_key(data, backend=default_backend())
    nums = key.public_numbers()
    if isinstance(key, rsa.RSAPublicKey):
        obj.type = lib.TPM2_ALG_RSA
        obj.parameters.rsaDetail.keyBits = key.key_size
        _int_to_buffer(nums.n, obj.unique.rsa)
        if nums.e != 65537:
            obj.parameters.rsaDetail.exponent = nums.e
        else:
            obj.parameters.rsaDetail.exponent = 0
    elif isinstance(key, ec.EllipticCurvePublicKey):
        obj.type = lib.TPM2_ALG_ECC
        curveid = _get_curveid(key.curve)
        if curveid is None:
            raise ValueError(f"unsupported curve: {key.curve.name}")
        obj.parameters.eccDetail.curveID = curveid
        _int_to_buffer(nums.x, obj.unique.ecc.x)
        _int_to_buffer(nums.y, obj.unique.ecc.y)
    else:
        raise RuntimeError(f"unsupported key type: {key.__class__.__name__}")


def private_from_pem(data, obj):
    key = load_pem_private_key(data, None, backend=default_backend())
    nums = key.private_numbers()
    if isinstance(key, rsa.RSAPrivateKey):
        obj.sensitiveArea.sensitiveType = lib.TPM2_ALG_RSA
        _int_to_buffer(nums.p, obj.sensitiveArea.sensitive.rsa)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        obj.sensitiveArea.sensitiveType = lib.TPM2_ALG_ECC
        _int_to_buffer(nums.private_value, obj.sensitiveArea.sensitive.ecc)
    else:
        raise RuntimeError(f"unsupported key type: {key.__class__.__name__}")


def public_to_pem(obj):
    key = None
    if obj.type == lib.TPM2_ALG_RSA:
        b = obj.unique.rsa.buffer
        n = int.from_bytes(b, byteorder="big")
        e = obj.parameters.rsaDetail.exponent
        if e == 0:
            e = 65537
        nums = rsa.RSAPublicNumbers(e, n)
        key = nums.public_key(backend=default_backend())
    elif obj.type == lib.TPM2_ALG_ECC:
        curve = _get_curve(obj.parameters.eccDetail.curveID)
        if curve is None:
            raise ValueError(
                f"unsupported curve: {obj.publicArea.parameters.eccDetail.curveID}"
            )
        x = int.from_bytes(obj.unique.ecc.x, byteorder="big")
        y = int.from_bytes(obj.unique.ecc.y, byteorder="big")
        nums = ec.EllipticCurvePublicNumbers(x, y, curve())
        key = nums.public_key(backend=default_backend())
    else:
        raise RuntimeError(f"unsupported key type: {obj.publicArea.type}")
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def getname(obj):
    dt = _get_digest(obj.nameAlg)
    if dt is None:
        raise ValueError(f"unsupported digest algorithm: {d}")
    d = hashes.Hash(dt(), backend=default_backend())
    mb = obj.Marshal()
    d.update(mb)
    b = d.finalize()
    db = obj.nameAlg.to_bytes(length=2, byteorder="big")
    name = db + b
    return name
