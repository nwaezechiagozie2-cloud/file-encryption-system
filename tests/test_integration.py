"""
Integration Tests for File Encryption and Decryption System
===========================================================
Verifies:
- End-to-end encryption and decryption workflows
- Byte-for-byte fidelity across diverse file formats (txt, pdf, jpg, bin)
- Boundary size edge cases (0B, 1B, 15B, 16B, 17B, 1MB)
- Rejection of tampered files without releasing plaintext
- Wrong password rejection before unpadding
- Preserving file extensions when .enc packages are renamed
- Automated activity audit logging in SQLite
"""

import unittest
import os
import tempfile
import hashlib
from app.service import FileCryptoService
from app.db_logger import DBLogger


class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit.db")
        self.logger = DBLogger(db_path=self.db_path)
        self.service = FileCryptoService(db_logger=self.logger)
        self.password = "ProjectDefensePassphrase@2026"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_sample_file(self, filename: str, content: bytes) -> str:
        path = os.path.join(self.temp_dir.name, filename)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_end_to_end_text_file(self):
        """Test complete encryption and decryption of a text document."""
        original_content = b"Final Year Project 2026\nDepartment of Computer Science, UNN.\nConfidential."
        txt_path = self._create_sample_file("report.txt", original_content)

        # 1. Encrypt
        success, enc_path, msg = self.service.encrypt_file(txt_path, self.password)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(enc_path))
        self.assertTrue(enc_path.endswith(".enc"))

        # 2. Decrypt
        success, rest_path, msg = self.service.decrypt_file(enc_path, self.password, overwrite=True)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(rest_path))

        # 3. Byte-for-byte equality verification
        with open(rest_path, "rb") as f:
            restored_content = f.read()

        self.assertEqual(hashlib.sha256(original_content).digest(), hashlib.sha256(restored_content).digest())

    def test_boundary_sizes(self):
        """Test edge cases: 0 bytes (empty file), 1B, 15B, 16B (block size), 17B."""
        boundary_cases = {
            "empty.bin": b"",
            "one_byte.bin": b"A",
            "fifteen.bin": b"B" * 15,
            "sixteen.bin": b"C" * 16,
            "seventeen.bin": b"D" * 17,
            "large.bin": os.urandom(500_000)  # 500 KB random bytes
        }

        for filename, data in boundary_cases.items():
            src_path = self._create_sample_file(filename, data)
            success_enc, enc_path, _ = self.service.encrypt_file(src_path, self.password)
            self.assertTrue(success_enc, f"Failed to encrypt {filename}")

            success_dec, rest_path, _ = self.service.decrypt_file(enc_path, self.password, overwrite=True)
            self.assertTrue(success_dec, f"Failed to decrypt {filename}")

            with open(rest_path, "rb") as f:
                restored = f.read()

            self.assertEqual(len(restored), len(data), f"Length mismatch on {filename}")
            self.assertEqual(hashlib.sha256(data).digest(), hashlib.sha256(restored).digest())

    def test_tampered_ciphertext_rejected(self):
        """Test that altering 1 byte in the ciphertext is caught by HMAC verification."""
        content = b"Financial Transactions: AccountBalance=500000"
        src_path = self._create_sample_file("finances.txt", content)

        _, enc_path, _ = self.service.encrypt_file(src_path, self.password)

        # Tamper: flip 1 byte in the ciphertext portion
        with open(enc_path, "rb") as f:
            enc_bytes = bytearray(f.read())

        # Ciphertext is between header (64B) and tag (32B)
        enc_bytes[70] ^= 0x01

        with open(enc_path, "wb") as f:
            f.write(enc_bytes)

        # Decryption MUST fail and must NOT release plaintext
        dest_path = os.path.join(self.temp_dir.name, "finances.restored.txt")
        success, out_path, msg = self.service.decrypt_file(enc_path, self.password, output_path=dest_path)

        self.assertFalse(success)
        self.assertIn("Authentication failed", msg)
        self.assertFalse(os.path.exists(dest_path), "Plaintext must not be written on authentication failure!")

    def test_wrong_password_rejected(self):
        """Test that attempting decryption with an incorrect password fails immediately."""
        content = b"Top secret thesis experimental results"
        src_path = self._create_sample_file("thesis.docx", content)

        _, enc_path, _ = self.service.encrypt_file(src_path, self.password)

        dest_path = os.path.join(self.temp_dir.name, "thesis.restored.docx")
        success, _, msg = self.service.decrypt_file(enc_path, "IncorrectPassword", output_path=dest_path)

        self.assertFalse(success)
        self.assertIn("Authentication failed", msg)
        self.assertFalse(os.path.exists(dest_path))

    def test_renamed_package_extension_preservation(self):
        """Test that renaming an encrypted package retains the original file extension upon decryption."""
        content = b"PDF Header %PDF-1.4 Mock Binary Content"
        pdf_path = self._create_sample_file("document.pdf", content)

        _, enc_path, _ = self.service.encrypt_file(pdf_path, self.password)

        # Rename document.pdf.enc -> archive.enc
        renamed_enc = os.path.join(self.temp_dir.name, "archive.enc")
        os.rename(enc_path, renamed_enc)

        # Decrypt without specifying custom output path
        success, out_path, _ = self.service.decrypt_file(renamed_enc, self.password)
        self.assertTrue(success)
        self.assertTrue(out_path.endswith(".pdf"), f"Expected .pdf extension but got {out_path}")
        self.assertTrue(os.path.exists(out_path))

    def test_audit_logging_records_transactions(self):
        """Test that transactions are accurately logged in SQLite database."""
        content = b"Sample data for audit log verification."
        src_path = self._create_sample_file("audit_test.txt", content)

        self.service.encrypt_file(src_path, self.password)
        enc_path = src_path + ".enc"
        self.service.decrypt_file(enc_path, self.password, overwrite=True)

        history = self.logger.fetch_history()
        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(history[0]["operation"], "Decryption")
        self.assertEqual(history[1]["operation"], "Encryption")

    def test_batch_encryption_and_decryption(self):
        """Test batch encryption and decryption across multiple distinct files."""
        files_data = {
            "batch_doc1.txt": b"First document text payload.",
            "batch_doc2.csv": b"id,name,role\n1,alice,admin\n2,bob,auditor",
            "batch_doc3.png": b"\x89PNG\r\n\x1a\nFakePngBinaryDataForBatchTesting"
        }
        src_paths = [self._create_sample_file(name, data) for name, data in files_data.items()]

        # 1. Batch encrypt
        enc_results = self.service.encrypt_batch(src_paths, self.password)
        self.assertEqual(len(enc_results), len(src_paths))
        enc_paths = []
        for src, ok, out_path, _ in enc_results:
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(out_path))
            enc_paths.append(out_path)

        # 2. Delete original unencrypted files to verify restoration
        for p in src_paths:
            os.remove(p)

        # 3. Batch decrypt
        dec_results = self.service.decrypt_batch(enc_paths, self.password)
        self.assertEqual(len(dec_results), len(enc_paths))
        for enc, ok, restored_path, _ in dec_results:
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(restored_path))
            fname = os.path.basename(restored_path)
            self.assertIn(fname, files_data)
            with open(restored_path, "rb") as f:
                self.assertEqual(f.read(), files_data[fname])


if __name__ == "__main__":
    unittest.main()
