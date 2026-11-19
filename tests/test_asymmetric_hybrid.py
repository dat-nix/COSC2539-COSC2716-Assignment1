import unittest
from dataclasses import replace

from asymmetric import HybridDecryptionError
from asymmetric.adversarial_runner import (
    CIPHERTEXT_TAMPERED,
    KEY_REPLACED,
    MALFORMED_PUBLIC,
    TAG_TAMPERED,
    _modified_envelope,
)
from asymmetric.common import ECDH_SCHEME, GCM_TAG_BYTES, RSA_SCHEME, X25519_SCHEME
from asymmetric.schemes import SCHEMES, generate_recipient_keypairs


class HybridCryptographyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = generate_recipient_keypairs(rsa_key_size=2048)

    def test_all_schemes_round_trip_bytes(self):
        message = b"hello" + bytes(range(32))
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme.name):
                private_key, public_key = self.keys[scheme.name]
                envelope = scheme.encrypt(message, public_key)
                self.assertEqual(envelope.scheme, scheme.name)
                self.assertEqual(len(envelope.tag), GCM_TAG_BYTES)
                outcome = scheme.attempt_decrypt(envelope, private_key)
                self.assertTrue(outcome.accepted)
                self.assertTrue(outcome.plaintext_released)
                self.assertEqual(outcome.plaintext, message)

    def test_ciphertext_and_tag_tampering_never_release_plaintext(self):
        message = b"a small payload for tampering tests"
        for scheme in SCHEMES:
            private_key, public_key = self.keys[scheme.name]
            envelope = scheme.encrypt(message, public_key)
            for scenario in (CIPHERTEXT_TAMPERED, TAG_TAMPERED):
                with self.subTest(scheme=scheme.name, scenario=scenario):
                    tampered = _modified_envelope(scheme.name, envelope, scenario)
                    outcome = scheme.attempt_decrypt(tampered, private_key)
                    self.assertFalse(outcome.accepted)
                    self.assertFalse(outcome.plaintext_released)
                    self.assertIsNone(outcome.plaintext)
                    self.assertTrue(outcome.aes_gcm_verification_reached)
                    with self.assertRaises(HybridDecryptionError):
                        scheme_module_decrypt(scheme.name, tampered, private_key)

    def test_scheme_specific_key_material_tampering_has_distinct_stages(self):
        message = b"key-material scenario"
        for scheme in SCHEMES:
            private_key, public_key = self.keys[scheme.name]
            envelope = scheme.encrypt(message, public_key)
            tampered = _modified_envelope(scheme.name, envelope, "key_material_tampered")
            outcome = scheme.attempt_decrypt(tampered, private_key)
            self.assertFalse(outcome.accepted)
            self.assertFalse(outcome.plaintext_released)
            self.assertIsNone(outcome.plaintext)
            if scheme.name == RSA_SCHEME:
                self.assertEqual(outcome.failure_stage, "rsa_oaep_unwrap")
                self.assertFalse(outcome.aes_gcm_verification_reached)
            else:
                self.assertTrue(outcome.key_agreement_completed)
                self.assertTrue(outcome.hkdf_completed)
                self.assertTrue(outcome.aes_gcm_verification_reached)
                self.assertEqual(outcome.failure_stage, "aes_gcm_authentication")

    def test_malformed_public_keys_fail_before_gcm(self):
        message = b"malformed public key"
        for scheme_name in (ECDH_SCHEME, X25519_SCHEME):
            scheme = next(item for item in SCHEMES if item.name == scheme_name)
            private_key, public_key = self.keys[scheme_name]
            envelope = scheme.encrypt(message, public_key)
            malformed = _modified_envelope(scheme_name, envelope, MALFORMED_PUBLIC)
            outcome = scheme.attempt_decrypt(malformed, private_key)
            self.assertFalse(outcome.accepted)
            self.assertFalse(outcome.plaintext_released)
            self.assertIsNone(outcome.plaintext)
            self.assertFalse(outcome.aes_gcm_verification_reached)
            self.assertIn(outcome.failure_stage, ("public_key_parse", "key_agreement"))

    def test_rsa_wrapped_key_and_malformed_envelope_are_rejected(self):
        private_key, public_key = self.keys[RSA_SCHEME]
        envelope = next(item for item in SCHEMES if item.name == RSA_SCHEME).encrypt(b"data", public_key)
        changed_key = _modified_envelope(RSA_SCHEME, envelope, "key_material_tampered")
        malformed = replace(envelope, nonce=b"short")
        for candidate, stage in ((changed_key, "rsa_oaep_unwrap"), (malformed, "envelope_validation")):
            outcome = next(item for item in SCHEMES if item.name == RSA_SCHEME).attempt_decrypt(candidate, private_key)
            self.assertFalse(outcome.accepted)
            self.assertFalse(outcome.plaintext_released)
            self.assertIsNone(outcome.plaintext)
            self.assertEqual(outcome.failure_stage, stage)

    def test_wrong_scheme_and_non_bytes_are_rejected(self):
        scheme = next(item for item in SCHEMES if item.name == X25519_SCHEME)
        private_key, public_key = self.keys[X25519_SCHEME]
        with self.assertRaises(TypeError):
            scheme.encrypt("text", public_key)
        envelope = scheme.encrypt(b"text", public_key)
        wrong = replace(envelope, scheme=ECDH_SCHEME)
        result = scheme.attempt_decrypt(wrong, private_key)
        self.assertFalse(result.accepted)
        self.assertEqual(result.failure_stage, "envelope_validation")


def scheme_module_decrypt(scheme_name, envelope, private_key):
    if scheme_name == RSA_SCHEME:
        from asymmetric.rsa_oaep_aes_gcm import decrypt
    elif scheme_name == ECDH_SCHEME:
        from asymmetric.ecdh_p256_aes_gcm import decrypt
    else:
        from asymmetric.x25519_aes_gcm import decrypt
    return decrypt(envelope, private_key)


if __name__ == "__main__":
    unittest.main()
