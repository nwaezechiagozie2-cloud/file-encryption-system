"""
Service Module
==============
High-level controller coordinating CryptoEngine, FileHandler, and DBLogger.
Provides a clean, unified API for encryption and decryption workflows.
"""

import os
from typing import Tuple, Optional, Callable
from .crypto_engine import CryptoEngine, AuthenticationError, PaddingError
from .file_handler import FileHandler, FileHandlerError, InvalidFileFormatError, FileLockedError
from .db_logger import DBLogger


class FileCryptoService:
    """Coordinates encryption, decryption, file I/O, and audit logging."""

    def __init__(self, db_logger: Optional[DBLogger] = None):
        self.logger = db_logger or DBLogger()

    def encrypt_file(
        self,
        input_path: str,
        password: str,
        output_path: Optional[str] = None,
        overwrite: bool = False,
        progress_cb: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, str, str]:
        """
        Execute full encryption pipeline for a target file.

        :param input_path: Path to the plaintext source file.
        :param password: User secret passphrase.
        :param output_path: Optional custom output destination (defaults to input_path + '.enc').
        :param overwrite: Whether to overwrite existing destination.
        :param progress_cb: Optional callback for status messages.
        :return: Tuple of (success: bool, final_path: str, message: str)
        """
        def update(msg: str):
            if progress_cb:
                progress_cb(msg)

        if not input_path or not os.path.exists(input_path):
            err_msg = f"Target file does not exist: {input_path}"
            self.logger.log_event(input_path or "UNKNOWN", "Encryption", f"Failed: {err_msg}")
            return False, "", err_msg

        if not password:
            err_msg = "Passphrase cannot be empty."
            self.logger.log_event(input_path, "Encryption", f"Failed: {err_msg}")
            return False, "", err_msg

        dest_path = output_path or FileHandler.get_default_encrypted_path(input_path)
        if os.path.exists(dest_path) and not overwrite:
            err_msg = f"Destination file already exists: {dest_path}"
            return False, dest_path, err_msg

        try:
            update("Reading source file...")
            plaintext = FileHandler.read_binary(input_path)
            original_size = len(plaintext)
            _, ext = os.path.splitext(input_path)

            update("Generating cryptographic keys (PBKDF2-HMAC-SHA256)...")
            salt = CryptoEngine.generate_salt()
            iv = CryptoEngine.generate_iv()
            iterations = CryptoEngine.DEFAULT_ITERATIONS

            aes_key, mac_key = CryptoEngine.derive_keys(password, salt, iterations)

            update("Encrypting payload (AES-256-CBC)...")
            ciphertext = CryptoEngine.encrypt(plaintext, aes_key, iv)

            update("Serializing metadata header and computing HMAC authentication tag...")
            header = FileHandler.pack_header(original_size, iterations, salt, iv, ext)
            auth_tag = CryptoEngine.compute_hmac(mac_key, header + ciphertext)

            final_payload = header + ciphertext + auth_tag

            update("Writing encrypted file to disk...")
            committed_path = FileHandler.write_binary_atomic(dest_path, final_payload, overwrite=overwrite)

            # Record audit transaction
            self.logger.log_event(input_path, "Encryption", f"Success: {committed_path}")
            update("Encryption complete.")

            return True, committed_path, "File encrypted successfully. Note: The unencrypted original file remains on disk."

        except FileLockedError as err:
            err_msg = str(err)
            self.logger.log_event(input_path, "Encryption", f"Failed (Locked): {err_msg}")
            return False, "", err_msg
        except Exception as err:
            err_msg = f"Encryption failed: {err}"
            self.logger.log_event(input_path, "Encryption", f"Exception: {err_msg}")
            return False, "", err_msg

    def decrypt_file(
        self,
        encrypted_path: str,
        password: str,
        output_path: Optional[str] = None,
        overwrite: bool = False,
        progress_cb: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, str, str]:
        """
        Execute full authenticated decryption pipeline for an encrypted file.

        :param encrypted_path: Path to the .enc file.
        :param password: User passphrase.
        :param output_path: Optional custom destination path.
        :param overwrite: Whether to overwrite existing destination.
        :param progress_cb: Optional callback for status messages.
        :return: Tuple of (success: bool, final_path: str, message: str)
        """
        def update(msg: str):
            if progress_cb:
                progress_cb(msg)

        if not encrypted_path or not os.path.exists(encrypted_path):
            err_msg = f"Encrypted file does not exist: {encrypted_path}"
            self.logger.log_event(encrypted_path or "UNKNOWN", "Decryption", f"Failed: {err_msg}")
            return False, "", err_msg

        if not password:
            err_msg = "Passphrase cannot be empty."
            self.logger.log_event(encrypted_path, "Decryption", f"Failed: {err_msg}")
            return False, "", err_msg

        try:
            update("Reading encrypted package...")
            blob = FileHandler.read_binary(encrypted_path)

            min_package_size = FileHandler.HEADER_SIZE + CryptoEngine.BLOCK_SIZE + CryptoEngine.TAG_SIZE
            if len(blob) < min_package_size:
                err_msg = "Corrupted file: Payload is shorter than the minimum valid encrypted package."
                self.logger.log_event(encrypted_path, "Decryption", f"Failed: {err_msg}")
                return False, "", err_msg

            # Extract structural components
            header_bytes = blob[:FileHandler.HEADER_SIZE]
            ciphertext = blob[FileHandler.HEADER_SIZE:-CryptoEngine.TAG_SIZE]
            stored_tag = blob[-CryptoEngine.TAG_SIZE:]

            update("Unpacking header metadata...")
            hdr = FileHandler.unpack_header(header_bytes)

            update("Deriving keys (PBKDF2-HMAC-SHA256)...")
            aes_key, mac_key = CryptoEngine.derive_keys(password, hdr["salt"], hdr["iterations"])

            update("Verifying cryptographic authentication tag (HMAC-SHA256)...")
            is_valid = CryptoEngine.verify_hmac(mac_key, header_bytes + ciphertext, stored_tag)
            if not is_valid:
                err_msg = "Authentication failed: Incorrect password or the encrypted file has been tampered with."
                self.logger.log_event(encrypted_path, "Decryption", "Failed: Authentication tag mismatch")
                return False, "", err_msg

            update("Decrypting payload (AES-256-CBC)...")
            plaintext = CryptoEngine.decrypt(ciphertext, aes_key, hdr["iv"])

            # Verify size integrity
            if len(plaintext) != hdr["original_size"]:
                err_msg = f"Integrity failure: Restored size ({len(plaintext)}) does not match expected size ({hdr['original_size']})."
                self.logger.log_event(encrypted_path, "Decryption", f"Failed: {err_msg}")
                return False, "", err_msg

            # Determine destination path
            dest_path = output_path or FileHandler.get_default_decrypted_path(encrypted_path, hdr["extension"])

            if os.path.exists(dest_path) and not overwrite:
                err_msg = f"Destination file already exists: {dest_path}"
                return False, dest_path, err_msg

            update("Writing restored file to disk...")
            committed_path = FileHandler.write_binary_atomic(dest_path, plaintext, overwrite=overwrite)

            self.logger.log_event(encrypted_path, "Decryption", f"Success: {committed_path}")
            update("Decryption complete.")

            return True, committed_path, f"File decrypted successfully. Restored to: {committed_path}"

        except InvalidFileFormatError as err:
            err_msg = f"Invalid format: {err}"
            self.logger.log_event(encrypted_path, "Decryption", f"Failed: {err_msg}")
            return False, "", err_msg
        except FileLockedError as err:
            err_msg = str(err)
            self.logger.log_event(encrypted_path, "Decryption", f"Failed (Locked): {err_msg}")
            return False, "", err_msg
        except Exception as err:
            err_msg = f"Decryption failed: {err}"
            self.logger.log_event(encrypted_path, "Decryption", f"Exception: {err_msg}")
            return False, "", err_msg

    def encrypt_batch(
        self,
        input_paths: list[str],
        password: str,
        overwrite: bool = False,
        progress_cb: Optional[Callable[[int, int, str], None]] = None
    ) -> list[Tuple[str, bool, str, str]]:
        """
        Encrypt multiple files in batch.

        :param input_paths: List of plaintext file paths.
        :param password: Secret passphrase.
        :param overwrite: Whether to overwrite existing destination files.
        :param progress_cb: Optional callback taking (current_index, total_count, current_filename).
        :return: List of tuples: (source_path, success, output_path, message)
        """
        results = []
        total = len(input_paths)
        for idx, file_path in enumerate(input_paths, 1):
            if progress_cb:
                progress_cb(idx, total, file_path)
            success, out_path, msg = self.encrypt_file(
                input_path=file_path,
                password=password,
                overwrite=overwrite
            )
            results.append((file_path, success, out_path, msg))
        return results

    def decrypt_batch(
        self,
        encrypted_paths: list[str],
        password: str,
        overwrite: bool = False,
        progress_cb: Optional[Callable[[int, int, str], None]] = None
    ) -> list[Tuple[str, bool, str, str]]:
        """
        Decrypt multiple files in batch.

        :param encrypted_paths: List of .enc file paths.
        :param password: Secret passphrase.
        :param overwrite: Whether to overwrite existing restored destinations.
        :param progress_cb: Optional callback taking (current_index, total_count, current_filename).
        :return: List of tuples: (source_path, success, output_path, message)
        """
        results = []
        total = len(encrypted_paths)
        for idx, file_path in enumerate(encrypted_paths, 1):
            if progress_cb:
                progress_cb(idx, total, file_path)
            success, out_path, msg = self.decrypt_file(
                encrypted_path=file_path,
                password=password,
                overwrite=overwrite
            )
            results.append((file_path, success, out_path, msg))
        return results
