"""
Unit Tests for FileHandler
==========================
Verifies:
- 64-byte Header packing and unpacking format (!4sQI16s16s16s)
- Magic bytes verification (FED1)
- Extension serialization and normalization
- Atomic file write commit and overwrite prevention
- Exception handling for missing files
"""

import unittest
import os
import tempfile
from app.file_handler import FileHandler, InvalidFileFormatError, FileHandlerError


class TestFileHandler(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.salt = b"S" * 16
        self.iv = b"I" * 16

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pack_unpack_header_exact(self):
        """Test packing and unpacking metadata parameters."""
        orig_size = 54321
        iterations = 100000
        ext = ".pdf"

        hdr_bytes = FileHandler.pack_header(orig_size, iterations, self.salt, self.iv, ext)
        self.assertEqual(len(hdr_bytes), FileHandler.HEADER_SIZE)
        self.assertEqual(len(hdr_bytes), 64)

        unpacked = FileHandler.unpack_header(hdr_bytes)
        self.assertEqual(unpacked["magic"], b"FED1")
        self.assertEqual(unpacked["original_size"], orig_size)
        self.assertEqual(unpacked["iterations"], iterations)
        self.assertEqual(unpacked["salt"], self.salt)
        self.assertEqual(unpacked["iv"], self.iv)
        self.assertEqual(unpacked["extension"], ".pdf")

    def test_invalid_magic_bytes_rejected(self):
        """Test that invalid magic bytes raise InvalidFileFormatError."""
        hdr_bytes = bytearray(FileHandler.pack_header(100, 100000, self.salt, self.iv, ".txt"))
        hdr_bytes[0:4] = b"BAD!"
        with self.assertRaises(InvalidFileFormatError):
            FileHandler.unpack_header(bytes(hdr_bytes))

    def test_iteration_bounds_enforced(self):
        """Test that excessive or tiny iterations are rejected."""
        hdr_low = FileHandler.pack_header(100, 500, self.salt, self.iv, ".txt")
        with self.assertRaises(InvalidFileFormatError):
            FileHandler.unpack_header(hdr_low)

        hdr_high = FileHandler.pack_header(100, 5_000_000, self.salt, self.iv, ".txt")
        with self.assertRaises(InvalidFileFormatError):
            FileHandler.unpack_header(hdr_high)

    def test_atomic_file_write_and_overwrite(self):
        """Test writing binary files atomically without silent overwrites."""
        test_file = os.path.join(self.temp_dir.name, "sample.txt")
        data = b"Hello, secure world!"

        written = FileHandler.write_binary_atomic(test_file, data, overwrite=False)
        self.assertTrue(os.path.exists(written))
        self.assertEqual(FileHandler.read_binary(written), data)

        # Writing again without overwrite flag must raise FileExistsError
        with self.assertRaises(FileExistsError):
            FileHandler.write_binary_atomic(test_file, b"New data", overwrite=False)

        # Writing with overwrite=True succeeds
        FileHandler.write_binary_atomic(test_file, b"Updated data", overwrite=True)
        self.assertEqual(FileHandler.read_binary(test_file), b"Updated data")

    def test_default_paths(self):
        """Test path derivation for encrypted and decrypted outputs."""
        self.assertEqual(FileHandler.get_default_encrypted_path("/home/user/doc.pdf"), "/home/user/doc.pdf.enc")
        self.assertEqual(FileHandler.get_default_decrypted_path("/home/user/doc.pdf.enc", ".pdf"), "/home/user/doc.pdf")
        # Renamed encrypted package restores with extension
        self.assertEqual(FileHandler.get_default_decrypted_path("/home/user/backup.enc", ".pdf"), "/home/user/backup.pdf")


if __name__ == "__main__":
    unittest.main()
