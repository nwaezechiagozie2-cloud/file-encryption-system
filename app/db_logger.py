"""
DBLogger Module
===============
Manages the local, serverless SQLite activity history database (local_audit.db).
Ensures atomic persistence of file encryption/decryption audit logs
while strictly excluding any passwords, keys, or plaintext content.
"""

import os
import sqlite3
import threading
from typing import List, Dict, Any, Optional


class DBLogger:
    """Thread-safe SQLite Activity Logger for the File Encryption System."""

    DEFAULT_DB_NAME: str = "local_audit.db"

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the database logger.

        :param db_path: Path to the SQLite database file (defaults to local_audit.db in app directory).
        """
        if db_path is None:
            # Place database in the user's working directory or next to main
            self.db_path = os.path.abspath(self.DEFAULT_DB_NAME)
        else:
            self.db_path = os.path.abspath(db_path)

        self._lock = threading.Lock()
        self.initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with appropriate timeout and row factory."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_database(self) -> None:
        """Initialize the database schema if it does not already exist."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS encryption_history (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        operation TEXT NOT NULL CHECK(operation IN ('Encryption', 'Decryption')),
                        status_message TEXT NOT NULL,
                        timestamp TEXT NOT NULL DEFAULT (DATETIME('now'))
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_time ON encryption_history(timestamp DESC);")
                conn.commit()

    def log_event(self, file_path: str, operation: str, status_message: str) -> Optional[int]:
        """
        Record a cryptographic transaction event in the local SQLite database.

        :param file_path: Path of the target file being processed.
        :param operation: 'Encryption' or 'Decryption'.
        :param status_message: Summary of the outcome (e.g. 'Success', or error details).
        :return: Inserted log_id or None if failed.
        """
        if operation not in ("Encryption", "Decryption"):
            raise ValueError(f"Invalid operation '{operation}'. Must be 'Encryption' or 'Decryption'.")

        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO encryption_history (file_path, operation, status_message, timestamp)
                        VALUES (?, ?, ?, DATETIME('now'));
                    """, (file_path, operation, status_message))
                    conn.commit()
                    return cursor.lastrowid
            except Exception as err:
                # Do not crash the application if audit logging fails
                print(f"[DBLogger Warning] Failed to insert audit log record: {err}")
                return None

    def fetch_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch the most recent activity logs for presentation in the GUI history viewer.

        :param limit: Maximum number of records to retrieve (default 100).
        :return: List of dictionary records.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT log_id, file_path, operation, status_message, timestamp
                    FROM encryption_history
                    ORDER BY log_id DESC
                    LIMIT ?;
                """, (limit,))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def clear_history(self) -> int:
        """Clear all audit history records."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM encryption_history;")
                conn.commit()
                return cursor.rowcount
