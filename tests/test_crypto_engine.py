"""
Unit Tests for CryptoEngine
===========================
Verifies:
- PBKDF2-HMAC-SHA256 key derivation (length, determinism, salt uniqueness)
- PKCS7 padding boundaries (0B, 1B, 15B, 16B, 17B, 1000B)
- AES-256-CBC encryption and decryption correctness
- HMAC-SHA256 authentication tag calculation and constant-time verification
- Tamper detection (flipping 1 bit in ciphertext causes HMAC failure)
- Wrong password causes authentication failure
"""

import unittest
from app.crypto_engine import CryptoEngine, PaddingError


class TestCryptoEngine(unittest.TestCase):

    def setUp(self):
        self.password = "StrongPassphrase!2026"
        self.salt = CryptoEngine.generate_salt()
        self.iv = CryptoEngine.generate_iv()
        # Use smaller iterations for fast test execution
        self.test_iterations = 2000

    def test_key_derivation_lengths_and_determinism(self):
        """Test that PBKDF2 derives exactly 32B AES key and 32B MAC key deterministically."""
        aes1, mac1 = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)
        aes2, mac2 = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)

        self.assertEqual(len(aes1), 32)
        self.assertEqual(len(mac1), 32)
        self.assertEqual(aes1, aes2)
        self.assertEqual(mac1, mac2)

    def test_key_derivation_different_passwords(self):
        """Test that different passwords yield different keys with the same salt."""
        aes1, mac1 = CryptoEngine.derive_keys("PasswordA", self.salt, self.test_iterations)
        aes2, mac2 = CryptoEngine.derive_keys("PasswordB", self.salt, self.test_iterations)

        self.assertNotEqual(aes1, aes2)
        self.assertNotEqual(mac1, mac2)

    def test_key_derivation_different_salts(self):
        """Test that the same password with different salts yields different keys."""
        salt2 = CryptoEngine.generate_salt()
        aes1, mac1 = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)
        aes2, mac2 = CryptoEngine.derive_keys(self.password, salt2, self.test_iterations)

        self.assertNotEqual(aes1, aes2)
        self.assertNotEqual(mac1, mac2)

    def test_empty_password_rejection(self):
        """Test that empty passphrases are strictly rejected."""
        with self.assertRaises(ValueError):
            CryptoEngine.derive_keys("", self.salt, self.test_iterations)

    def test_pkcs7_padding_boundaries(self):
        """Test PKCS7 padding across various block boundaries (0B, 1B, 15B, 16B, 17B, 100B)."""
        test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 100, 1024]
        for size in test_sizes:
            data = b"X" * size
            padded = CryptoEngine.pad(data)
            self.assertEqual(len(padded) % 16, 0)
            unpadded = CryptoEngine.unpad(padded)
            self.assertEqual(unpadded, data)

    def test_invalid_pkcs7_padding(self):
        """Test that corrupted padding bytes trigger PaddingError."""
        corrupted = b"123456789012345\x00"  # Invalid 0x00 padding byte
        with self.assertRaises(PaddingError):
            CryptoEngine.unpad(corrupted)

    def test_aes_encryption_decryption_roundtrip(self):
        """Test end-to-end AES-256-CBC roundtrip accuracy."""
        aes_key, _ = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)
        plaintext = b"This is a confidential message requiring strong encryption."

        ciphertext = CryptoEngine.encrypt(plaintext, aes_key, self.iv)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(len(ciphertext) % 16, 0)

        recovered = CryptoEngine.decrypt(ciphertext, aes_key, self.iv)
        self.assertEqual(recovered, plaintext)

    def test_hmac_authentication_tag_and_verification(self):
        """Test HMAC-SHA256 generation and constant-time verification."""
        _, mac_key = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)
        message = b"HeaderBytesAndCiphertextCombined"

        tag = CryptoEngine.compute_hmac(mac_key, message)
        self.assertEqual(len(tag), 32)
        self.assertTrue(CryptoEngine.verify_hmac(mac_key, message, tag))

        # Tampered message must fail verification
        tampered_msg = b"HeaderBytesAndCiphertextCombinel"  # 1 bit flipped
        self.assertFalse(CryptoEngine.verify_hmac(mac_key, tampered_msg, tag))

        # Tampered tag must fail verification
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01
        self.assertFalse(CryptoEngine.verify_hmac(mac_key, message, bytes(tampered_tag)))

    def test_wrong_password_fails_authentication(self):
        """Test that a different password produces a different MAC key that fails tag verification."""
        _, mac_key_correct = CryptoEngine.derive_keys(self.password, self.salt, self.test_iterations)
        _, mac_key_wrong = CryptoEngine.derive_keys("WrongPassphrase", self.salt, self.test_iterations)

        message = b"AuthenticatedPayload12345"
        tag = CryptoEngine.compute_hmac(mac_key_correct, message)

        self.assertTrue(CryptoEngine.verify_hmac(mac_key_correct, message, tag))
        self.assertFalse(CryptoEngine.verify_hmac(mac_key_wrong, message, tag))


if __name__ == "__main__":
    unittest.main()
