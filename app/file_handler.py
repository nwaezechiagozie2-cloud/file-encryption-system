"""
FileHandler Module
==================
Manages all file system interactions, binary input/output streams,
big-endian binary header metadata serialization/deserialization,
path sanitization, and atomic file write commits.
"""

import os
import struct
import tempfile
from typing import Dict, Any, Tuple


class FileHandlerError(Exception):
    """Base exception for file handling errors."""
    pass


class InvalidFileFormatError(FileHandlerError):
    """Raised when the file header does not match the FED1 magic bytes or format."""
    pass


class FileLockedError(FileHandlerError):
    """Raised when the target file is locked by another process (e.g. Word or Adobe Reader)."""
    pass


class FileHandler:
    """Handles raw binary file I/O and metadata serialization."""

    MAGIC: bytes = b"FED1"                       # 4-byte File Encryption Decryption Magic Bytes
    HEADER_FORMAT: str = "!4sQI16s16s16s"        # Big-endian: magic(4), size(8), iterations(4), salt(16), iv(16), ext(16)
    HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)  # Exactly 64 bytes
    TAG_SIZE: int = 32                           # 32-byte HMAC-SHA256 authentication tag
    MAX_REASONABLE_ITERATIONS: int = 2_000_000   # Guard against malicious KDF parameters

    @classmethod
    def pack_header(cls, original_size: int, iterations: int, salt: bytes, iv: bytes, ext: str) -> bytes:
        """
        Pack metadata parameters into a fixed 64-byte big-endian binary header.

        :param original_size: Length of plaintext in bytes before padding.
        :param iterations: PBKDF2 iteration count.
        :param salt: 16-byte random salt.
        :param iv: 16-byte random IV.
        :param ext: Original file extension string (e.g., '.pdf', '.docx').
        :return: 64-byte serialized header.
        """
        if len(salt) != 16:
            raise ValueError("Salt must be exactly 16 bytes.")
        if len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes.")

        # Clean and pad extension to 16 bytes
        ext_clean = ext.strip().lower()
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = "." + ext_clean
        ext_bytes = ext_clean.encode("utf-8")[:16]
        ext_padded = ext_bytes.ljust(16, b"\x00")

        return struct.pack(cls.HEADER_FORMAT, cls.MAGIC, original_size, iterations, salt, iv, ext_padded)

    @classmethod
    def unpack_header(cls, header_bytes: bytes) -> Dict[str, Any]:
        """
        Unpack and validate a 64-byte binary header.

        :param header_bytes: 64-byte raw slice from the start of the file.
        :return: Dictionary containing original_size, iterations, salt, iv, and extension.
        """
        if len(header_bytes) != cls.HEADER_SIZE:
            raise InvalidFileFormatError(f"Header must be exactly {cls.HEADER_SIZE} bytes.")

        magic, original_size, iterations, salt, iv, ext_padded = struct.unpack(cls.HEADER_FORMAT, header_bytes)

        if magic != cls.MAGIC:
            raise InvalidFileFormatError(f"Invalid file format: Magic bytes {magic!r} do not match {cls.MAGIC!r}.")

        if iterations < 1000 or iterations > cls.MAX_REASONABLE_ITERATIONS:
            raise InvalidFileFormatError(f"KDF iteration count ({iterations}) is outside supported security bounds.")

        # Decode extension
        ext_clean = ext_padded.decode("utf-8", errors="ignore").rstrip("\x00")

        return {
            "magic": magic,
            "original_size": original_size,
            "iterations": iterations,
            "salt": salt,
            "iv": iv,
            "extension": ext_clean
        }

    @classmethod
    def read_binary(cls, file_path: str) -> bytes:
        """
        Read binary stream from disk with comprehensive OS error trapping.

        :param file_path: Target file path.
        :return: Raw bytes.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.path.isfile(file_path):
            raise FileHandlerError(f"Path is not a regular file: {file_path}")

        try:
            with open(file_path, "rb") as f:
                return f.read()
        except PermissionError as err:
            raise FileLockedError(
                f"Permission denied: The file '{os.path.basename(file_path)}' may be in use by another program "
                f"(such as Word, Excel, or Adobe Reader) or requires elevated permissions."
            ) from err
        except OSError as err:
            raise FileHandlerError(f"Operating system I/O error reading file: {err}") from err

    @classmethod
    def write_binary_atomic(cls, file_path: str, data: bytes, overwrite: bool = False) -> str:
        """
        Safely write data to disk using an atomic temporary file.
        If an error occurs midway, existing files are preserved without truncation.

        :param file_path: Target destination path.
        :param data: Bytes to write.
        :param overwrite: Whether to allow replacing an existing file.
        :return: The canonical path of the written file.
        """
        if os.path.exists(file_path) and not overwrite:
            raise FileExistsError(f"Destination file already exists: {file_path}")

        dest_dir = os.path.dirname(os.path.abspath(file_path)) or "."
        os.makedirs(dest_dir, exist_ok=True)

        # Write to a secure temporary file in the same directory, then rename atomically
        temp_fd, temp_path = tempfile.mkstemp(dir=dest_dir, prefix=".fed_tmp_")
        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename / replace
            os.replace(temp_path, file_path)
            return os.path.abspath(file_path)
        except Exception as err:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise FileHandlerError(f"Failed to safely write file '{file_path}': {err}") from err

    @classmethod
    def get_default_encrypted_path(cls, input_path: str) -> str:
        """Derive default encrypted output path by appending .enc."""
        return input_path + ".enc"

    @classmethod
    def get_default_decrypted_path(cls, encrypted_path: str, restored_ext: str = "") -> str:
        """
        Derive default restored plaintext output path, restoring proper extension.
        """
        base_dir, file_name = os.path.split(encrypted_path)

        if file_name.lower().endswith(".enc"):
            stem = file_name[:-4]
        else:
            stem = file_name + ".restored"

        # Check if stem already has an extension
        stem_name, stem_ext = os.path.splitext(stem)

        if restored_ext:
            if not restored_ext.startswith("."):
                restored_ext = "." + restored_ext
            if stem_ext.lower() != restored_ext.lower():
                stem = stem + restored_ext
        elif not stem_ext:
            stem = stem + ".restored"

        return os.path.join(base_dir, stem)
