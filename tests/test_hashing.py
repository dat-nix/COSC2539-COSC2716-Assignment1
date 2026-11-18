import hashlib
import unittest

from hashing import blake2b_256, sha256, sha3_256


class HashingTests(unittest.TestCase):
    algorithms = (
        ("SHA-256", sha256, hashlib.sha256),
        ("SHA3-256", sha3_256, hashlib.sha3_256),
        ("BLAKE2b-256", blake2b_256, lambda data: hashlib.blake2b(data, digest_size=32)),
    )

    def test_known_digest_values(self):
        data = b"abc"
        expected = {
            "SHA-256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "BLAKE2b-256": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        }
        for name, digest_function, _ in self.algorithms:
            with self.subTest(algorithm=name):
                self.assertEqual(digest_function(data).hex(), expected[name])

    def test_same_input_has_same_digest(self):
        for name, digest_function, _ in self.algorithms:
            with self.subTest(algorithm=name):
                self.assertEqual(digest_function(b"sample"), digest_function(b"sample"))

    def test_modified_input_has_different_digest(self):
        for name, digest_function, _ in self.algorithms:
            with self.subTest(algorithm=name):
                self.assertNotEqual(digest_function(b"sample"), digest_function(b"samplf"))

    def test_digest_is_32_bytes_and_hex_is_64_characters(self):
        for name, digest_function, _ in self.algorithms:
            with self.subTest(algorithm=name):
                result = digest_function(b"sample")
                self.assertEqual(len(result), 32)
                self.assertEqual(len(result.hex()), 64)
                self.assertRegex(result.hex(), r"\A[0-9a-f]{64}\Z")

    def test_functions_accept_bytes_and_match_hashlib(self):
        data = bytes(range(256))
        for name, digest_function, reference_function in self.algorithms:
            with self.subTest(algorithm=name):
                self.assertEqual(digest_function(data), reference_function(data).digest())


if __name__ == "__main__":
    unittest.main()
