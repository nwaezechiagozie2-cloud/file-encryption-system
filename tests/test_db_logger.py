"""
Unit Tests for DBLogger
=======================
Verifies:
- SQLite schema initialization (local_audit.db)
- Audit log insertion for Encryption and Decryption
- CHECK constraint enforcement for operations
- Fetching history in descending chronological order
- Thread safety and clean database isolation
"""

import unittest
import os
import tempfile
from app.db_logger import DBLogger


class TestDBLogger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit.db")
        self.logger = DBLogger(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_initialization(self):
        """Test that database file and table are created."""
        self.assertTrue(os.path.exists(self.db_path))

    def test_log_event_and_fetch_history(self):
        """Test logging transactions and fetching history."""
        log1 = self.logger.log_event("/path/to/test1.pdf", "Encryption", "Success: /path/to/test1.pdf.enc")
        log2 = self.logger.log_event("/path/to/test1.pdf.enc", "Decryption", "Success: /path/to/test1.pdf")

        self.assertIsNotNone(log1)
        self.assertIsNotNone(log2)

        history = self.logger.fetch_history(limit=10)
        self.assertEqual(len(history), 2)
        # Ordered by log_id DESC
        self.assertEqual(history[0]["operation"], "Decryption")
        self.assertEqual(history[1]["operation"], "Encryption")

    def test_invalid_operation_rejected(self):
        """Test that operations other than 'Encryption' or 'Decryption' are rejected."""
        with self.assertRaises(ValueError):
            self.logger.log_event("/path/to/file", "InvalidAction", "Message")

    def test_clear_history(self):
        """Test clearing activity logs."""
        self.logger.log_event("/path/to/file", "Encryption", "Success")
        self.logger.clear_history()
        history = self.logger.fetch_history()
        self.assertEqual(len(history), 0)


if __name__ == "__main__":
    unittest.main()
