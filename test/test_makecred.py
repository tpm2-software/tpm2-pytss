#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""
import unittest

from tpm2_pytss import *
from tpm2_pytss.makecred import *
from .TSS2_BaseTest import TSS2_EsapiTest


class MakeCredTest(TSS2_EsapiTest):
    def test_generate_seed_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.CreatePrimary(insens)
        seed, enc_seed = generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(
            str(e.exception), f"unsupported digest algorithm {TPM2_ALG.LAST + 1}"
        )

        public.publicArea.type = TPM2_ALG.NULL
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(str(e.exception), f"unsupported key type: {TPM2_ALG.NULL}")

    def test_generate_seed_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        _, public, _, _, _ = self.ectx.CreatePrimary(insens, "ecc")
        seed, enc_seed = generate_seed(public.publicArea, b"test")

        public.publicArea.nameAlg = TPM2_ALG.LAST + 1
        with self.assertRaises(ValueError) as e:
            generate_seed(public.publicArea, b"test")
        self.assertEqual(
            str(e.exception), f"unsupported digest algorithm {TPM2_ALG.LAST + 1}"
        )

    def test_MakeCredential_rsa(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.CreatePrimary(insens)
        private, public, _, _, _ = self.ectx.Create(phandle, insens)
        credblob, secret = MakeCredential(parent, b"credential data", public.getName())
        handle = self.ectx.Load(phandle, private, public)
        certinfo = self.ectx.ActivateCredential(handle, phandle, credblob, secret)
        self.assertEqual(b"credential data", bytes(certinfo))

    def test_MakeCredential_ecc(self):
        insens = TPM2B_SENSITIVE_CREATE()
        phandle, parent, _, _, _ = self.ectx.CreatePrimary(insens, "ecc")
        private, public, _, _, _ = self.ectx.Create(phandle, insens, "ecc")
        credblob, secret = MakeCredential(parent, b"credential data", public.getName())
        handle = self.ectx.Load(phandle, private, public)
        certinfo = self.ectx.ActivateCredential(handle, phandle, credblob, secret)
        self.assertEqual(b"credential data", bytes(certinfo))
