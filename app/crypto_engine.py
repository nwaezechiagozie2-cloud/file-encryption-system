"""
CryptoEngine Module
===================
Encapsulates all cryptographic primitives and algorithms for the
File Encryption and Decryption System:
- PBKDF2-HMAC-SHA256 Key Derivation (AES-256 Key + HMAC Key)
- AES-256-CBC Block Encryption and Decryption
- PKCS7 Padding and Unpadding
- HMAC-SHA256 Message Authentication Code (Encrypt-then-MAC)
- Cryptographically Secure Random Salt and IV Generation
"""

import hashlib
import hmac
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

try:
    from Crypto.Util.Padding import pad as pkcs7_pad, unpad as pkcs7_unpad
except ImportError:
    # Standard RFC 5652 PKCS#7 implementation fallback
    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    def pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
        if not padded_data:
            raise ValueError("Empty data cannot be unpadded.")
        pad_len = padded_data[-1]
        if pad_len < 1 or pad_len > block_size or len(padded_data) < pad_len:
            raise ValueError("Invalid padding length.")
        if padded_data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding bytes are corrupted.")
        return padded_data[:-pad_len]


class CryptoEngineError(Exception):
    """Base exception class for cryptographic operations."""
    pass


class AuthenticationError(CryptoEngineError):
    """Raised when HMAC authentication tag verification fails (wrong password or altered file)."""
    pass


class PaddingError(CryptoEngineError):
    """Raised when PKCS7 unpadding fails."""
    pass


class CryptoEngine:
    """Core cryptographic engine implementing AES-256-CBC with PBKDF2 and HMAC-SHA256."""

    BLOCK_SIZE: int = 16      # AES block size in bytes (128 bits)
    KEY_SIZE: int = 32        # AES-256 key size in bytes (256 bits)
    MAC_KEY_SIZE: int = 32    # HMAC-SHA256 key size in bytes (256 bits)
    SALT_SIZE: int = 16       # PBKDF2 salt size in bytes (128 bits)
    IV_SIZE: int = 16         # AES CBC initialization vector size in bytes (128 bits)
    TAG_SIZE: int = 32        # HMAC-SHA256 tag size in bytes (256 bits)
    DEFAULT_ITERATIONS: int = 100_000  # NIST recommended minimum for PBKDF2

    @staticmethod
    def generate_salt(size: int = SALT_SIZE) -> bytes:
        """Generate cryptographically secure random bytes for PBKDF2 salt."""
        return get_random_bytes(size)

    @staticmethod
    def generate_iv(size: int = IV_SIZE) -> bytes:
        """Generate cryptographically secure random bytes for AES CBC Initialization Vector."""
        return get_random_bytes(size)

    @classmethod
    def derive_keys(cls, password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> Tuple[bytes, bytes]:
        """
        Derive two independent 256-bit keys using PBKDF2-HMAC-SHA256:
        - aes_key: 32 bytes for AES-256-CBC encryption
        - mac_key: 32 bytes for HMAC-SHA256 integrity authentication

        :param password: User secret passphrase string.
        :param salt: 16-byte cryptographically secure random salt.
        :param iterations: Work factor (default 100,000 iterations).
        :return: Tuple (aes_key, mac_key)
        """
        if not password:
            raise ValueError("Passphrase cannot be empty.")
        if not salt or len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes.")
        if iterations < 1000:
            raise ValueError("Iterations count must be at least 1000.")

        password_bytes = password.encode("utf-8")
        total_key_len = cls.KEY_SIZE + cls.MAC_KEY_SIZE  # 64 bytes total

        key_material = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password_bytes,
            salt=salt,
            iterations=iterations,
            dklen=total_key_len
        )

        aes_key = key_material[:cls.KEY_SIZE]
        mac_key = key_material[cls.KEY_SIZE:cls.KEY_SIZE + cls.MAC_KEY_SIZE]
        return aes_key, mac_key

    @classmethod
    def pad(cls, data: bytes) -> bytes:
        """Apply standard PKCS7 padding to align with AES 16-byte block boundary."""
        return pkcs7_pad(data, cls.BLOCK_SIZE)

    @classmethod
    def unpad(cls, padded_data: bytes) -> bytes:
        """Strip PKCS7 padding from decrypted plaintext, validating byte integrity."""
        try:
            return pkcs7_unpad(padded_data, cls.BLOCK_SIZE)
        except ValueError as err:
            raise PaddingError(f"Invalid PKCS7 padding: {err}") from err

    @classmethod
    def encrypt(cls, plaintext: bytes, aes_key: bytes, iv: bytes) -> bytes:
        """
        Encrypt raw plaintext bytes using AES-256 in CBC mode with PKCS7 padding.

        :param plaintext: Input byte stream.
        :param aes_key: 32-byte (256-bit) encryption key.
        :param iv: 16-byte random Initialization Vector.
        :return: Ciphertext bytes.
        """
        if len(aes_key) != cls.KEY_SIZE:
            raise ValueError(f"AES key must be exactly {cls.KEY_SIZE} bytes.")
        if len(iv) != cls.IV_SIZE:
            raise ValueError(f"IV must be exactly {cls.IV_SIZE} bytes.")

        padded_plaintext = cls.pad(plaintext)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded_plaintext)

    @classmethod
    def decrypt(cls, ciphertext: bytes, aes_key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext bytes using AES-256 in CBC mode and strip PKCS7 padding.

        :param ciphertext: Encrypted payload bytes (must be a multiple of 16).
        :param aes_key: 32-byte (256-bit) encryption key.
        :param iv: 16-byte Initialization Vector.
        :return: Unpadded plaintext bytes.
        """
        if len(aes_key) != cls.KEY_SIZE:
            raise ValueError(f"AES key must be exactly {cls.KEY_SIZE} bytes.")
        if len(iv) != cls.IV_SIZE:
            raise ValueError(f"IV must be exactly {cls.IV_SIZE} bytes.")
        if len(ciphertext) % cls.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of the 16-byte block size.")

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        return cls.unpad(decrypted_padded)

    @classmethod
    def compute_hmac(cls, mac_key: bytes, message: bytes) -> bytes:
        """
        Compute 32-byte HMAC-SHA256 authentication digest over a message.

        :param mac_key: 32-byte authentication key.
        :param message: Header bytes + Ciphertext bytes.
        :return: 32-byte authentication tag.
        """
        return hmac.new(mac_key, message, hashlib.sha256).digest()

    @classmethod
    def verify_hmac(cls, mac_key: bytes, message: bytes, expected_tag: bytes) -> bool:
        """
        Verify the HMAC-SHA256 tag in constant time using hmac.compare_digest.
        Prevents timing-attack vulnerabilities.

        :param mac_key: 32-byte authentication key.
        :param message: Header bytes + Ciphertext bytes.
        :param expected_tag: The 32-byte tag stored in the encrypted package.
        :return: True if tag matches exactly, False otherwise.
        """
        actual_tag = cls.compute_hmac(mac_key, message)
        return hmac.compare_digest(actual_tag, expected_tag)
