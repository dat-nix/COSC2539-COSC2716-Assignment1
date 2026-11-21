"""Functional checks for the short, presentation-only demo interface."""

from contextlib import redirect_stdout
from io import StringIO
import unittest

from demo.run_demo import run_hashing_demo, run_hybrid_demo, run_symmetric_demo


class PresentationDemoTests(unittest.TestCase):
    def capture(self, function):
        output = StringIO()
        with redirect_stdout(output):
            function()
        return output.getvalue()

    def test_hashing_shows_trusted_digest_rejection_and_recomputed_match(self):
        output = self.capture(run_hashing_demo)
        self.assertIn("Modified data vs trusted digest: REJECTED", output)
        self.assertIn("attacker-recomputed digest: MATCHES", output)

    def test_symmetric_rejects_tampered_tag_without_plaintext(self):
        output = self.capture(run_symmetric_demo)
        self.assertIn("Valid envelope: accepted; plaintext matches: True", output)
        self.assertIn("Tampered authentication tag: REJECTED", output)
        self.assertIn("Plaintext returned after failed authentication: False", output)

    def test_hybrid_rejects_tampered_tag_without_plaintext(self):
        output = self.capture(run_hybrid_demo)
        self.assertIn("Valid envelope: accepted; plaintext matches: True", output)
        self.assertIn("failure stage: aes_gcm_authentication", output)
        self.assertIn("Plaintext released after failure: False", output)


if __name__ == "__main__":
    unittest.main()
