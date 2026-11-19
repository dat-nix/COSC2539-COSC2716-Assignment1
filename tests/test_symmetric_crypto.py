import dataclasses
import unittest
from unittest import mock

from symmetric.aes_cbc_hmac import _decrypt_cbc
from symmetric.common import InvalidCiphertextError
from symmetric.schemes import SCHEMES


class SymmetricCryptographyTests(unittest.TestCase):
    def setUp(self):
        self.plaintexts = (b"", b"hello", bytes(range(255)))

    def test_all_schemes_round_trip_empty_and_non_block_aligned_plaintext(self):
        for scheme in SCHEMES:
            key = scheme.generate_key()
            for plaintext in self.plaintexts:
                with self.subTest(scheme=scheme.name, length=len(plaintext)):
                    envelope = scheme.encrypt(plaintext, key)
                    self.assertEqual(scheme.decrypt(envelope, key), plaintext)

    def test_fresh_encryption_produces_distinct_envelopes(self):
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme.name):
                key = scheme.generate_key()
                self.assertNotEqual(
                    scheme.encrypt(b"same message", key),
                    scheme.encrypt(b"same message", key),
                )

    def test_key_nonce_iv_and_authentication_field_lengths(self):
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme.name):
                key = scheme.generate_key()
                envelope = scheme.encrypt(b"length checks", key)
                if "CBC" in scheme.name:
                    encryption_key, mac_key = key
                    self.assertEqual(len(encryption_key), 32)
                    self.assertEqual(len(mac_key), 32)
                    self.assertNotEqual(encryption_key, mac_key)
                    self.assertEqual(len(envelope.iv), 16)
                    self.assertEqual(len(envelope.mac), 32)
                else:
                    self.assertEqual(len(key), 32)
                    self.assertEqual(len(envelope.nonce), 12)
                    self.assertEqual(len(envelope.tag), 16)

    def test_ciphertext_authentication_nonce_key_and_malformed_failures_release_no_plaintext(self):
        for scheme in SCHEMES:
            key = scheme.generate_key()
            envelope = scheme.encrypt(b"authenticated message", key)
            if "CBC" in scheme.name:
                wrong_key = scheme.generate_key()
                variants = (
                    dataclasses.replace(envelope, ciphertext=bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:]),
                    dataclasses.replace(envelope, mac=bytes([envelope.mac[0] ^ 1]) + envelope.mac[1:]),
                    dataclasses.replace(envelope, iv=bytes([envelope.iv[0] ^ 1]) + envelope.iv[1:]),
                    dataclasses.replace(envelope, ciphertext=None),
                )
            else:
                wrong_key = scheme.generate_key()
                variants = (
                    dataclasses.replace(envelope, ciphertext=bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:]),
                    dataclasses.replace(envelope, tag=bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]),
                    dataclasses.replace(envelope, nonce=bytes([envelope.nonce[0] ^ 1]) + envelope.nonce[1:]),
                    dataclasses.replace(envelope, ciphertext=None),
                )
            errors = []
            for invalid in variants:
                with self.subTest(scheme=scheme.name, envelope=invalid):
                    with self.assertRaises(InvalidCiphertextError) as raised:
                        scheme.decrypt(invalid, key)
                    errors.append((type(raised.exception), str(raised.exception)))
            with self.subTest(scheme=scheme.name, wrong_key=True):
                with self.assertRaises(InvalidCiphertextError) as raised:
                    scheme.decrypt(envelope, wrong_key)
                errors.append((type(raised.exception), str(raised.exception)))
            self.assertEqual(len(set(errors)), 1)

    def test_cbc_checks_mac_before_calling_decrypt_or_unpadding(self):
        from symmetric import aes_cbc_hmac

        key = aes_cbc_hmac.generate_key()
        envelope = aes_cbc_hmac.encrypt(b"do not decrypt before MAC", key)
        bad_mac = dataclasses.replace(envelope, mac=b"\x00" + envelope.mac[1:])
        with mock.patch("symmetric.aes_cbc_hmac._decrypt_cbc", wraps=_decrypt_cbc) as decrypt_mock:
            with self.assertRaises(InvalidCiphertextError):
                aes_cbc_hmac.decrypt(bad_mac, key)
            decrypt_mock.assert_not_called()

        bad_iv = dataclasses.replace(envelope, iv=b"\x00" + envelope.iv[1:])
        with mock.patch("symmetric.aes_cbc_hmac._decrypt_cbc", wraps=_decrypt_cbc) as decrypt_mock:
            with self.assertRaises(InvalidCiphertextError):
                aes_cbc_hmac.decrypt(bad_iv, key)
            decrypt_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
