"""Functional checks for the presentation-only demo interface."""

from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch

from demo.run_demo import _interactive_menu, run_hashing_demo, run_hybrid_demo, run_symmetric_demo


class PresentationDemoTests(unittest.TestCase):
    def capture(self, function):
        output = StringIO()
        with redirect_stdout(output):
            function()
        return output.getvalue()

    def test_hashing_covers_all_algorithms_and_trust_boundary(self):
        output = self.capture(run_hashing_demo)
        for name in ("SHA-256", "SHA3-256", "BLAKE2b-256"):
            self.assertIn(name, output)
        self.assertEqual(output.count("[MISMATCH]"), 3)
        self.assertEqual(output.count("[MATCHED]"), 3)

    def test_symmetric_covers_all_schemes_and_releases_no_invalid_plaintext(self):
        output = self.capture(run_symmetric_demo)
        for name in ("AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CBC + HMAC-SHA256"):
            self.assertIn(name, output)
        self.assertEqual(output.count("[REJECTED]"), 7)
        self.assertEqual(output.count("plaintext=None"), 7)
        self.assertIn("MAC verification -> CBC decryption/unpadding", output)

    def test_hybrid_covers_all_schemes_and_failure_stages(self):
        output = self.capture(run_hybrid_demo)
        for name in ("RSA-OAEP + AES-256-GCM", "ECDH P-256 + HKDF + AES-GCM", "X25519 + HKDF + AES-GCM"):
            self.assertIn(name, output)
        self.assertEqual(output.count("[REJECTED]"), 7)
        self.assertEqual(output.count("plaintext=None"), 7)
        for stage in ("envelope_validation", "oaep_unwrap", "aes_gcm_authentication"):
            self.assertIn(f"stage={stage}", output)

    def test_interactive_menu_identifies_security_functions_and_can_exit(self):
        with patch("builtins.input", return_value="q"):
            output = self.capture(_interactive_menu)
        self.assertIn("Hashing", output)
        self.assertIn("Integrity checking", output)
        self.assertIn("Symmetric encryption", output)
        self.assertIn("Confidentiality, authentication, and tamper rejection", output)
        self.assertIn("Hybrid encryption", output)
        self.assertIn("Public-key key handling", output)
        self.assertIn("No benchmark results were written", output)


if __name__ == "__main__":
    unittest.main()
