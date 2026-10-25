# File Encryption and Decryption System

**Department of Computer Science, University of Nigeria, Nsukka (UNN)**  
**B.Sc. Final Year Project Implementation**

---

## 1. Overview
The **File Encryption and Decryption System** is an offline, desktop cryptographic software utility engineered in Python. It provides authenticated, high-performance file protection using:
* **AES-256-CBC:** Symmetric block cipher operating with a 256-bit key and standard PKCS7 padding.
* **PBKDF2-HMAC-SHA256:** Password-based Key Derivation Function with a 16-byte random salt and 100,000 iterations to derive a 256-bit AES encryption key and a 256-bit MAC key.
* **HMAC-SHA256 (Encrypt-then-MAC):** Cryptographic authentication tag covering both metadata and ciphertext, ensuring tampering or incorrect passwords are detected in constant time *before* any plaintext is released.
* **Preserved File Extension Header:** Packed binary envelope format (`FED1`) that preserves the original file extension so renamed `.enc` packages restore with their native file type.
* **Asynchronous Desktop GUI:** Built using Python's `tkinter` and `ttk` with background worker threading to keep the interface responsive during heavy cryptographic operations.
* **Local SQLite Audit Logger:** Maintains an automated, zero-knowledge operational history (`local_audit.db`) of all encryption and decryption events.

---

## 2. Project Directory Structure

```text
file_encryption_system/
├── app/
│   ├── __init__.py           # Package exports
│   ├── crypto_engine.py      # AES-256-CBC, PBKDF2, PKCS7, HMAC-SHA256
│   ├── file_handler.py       # Binary I/O, !4sQI16s16s16s header, atomic writes
│   ├── db_logger.py          # SQLite local_audit.db connection & history
│   ├── service.py            # High-level crypto controller & pipeline
│   └── gui.py                # Tkinter modern desktop GUI & history modal
├── tests/
│   ├── __init__.py
│   ├── test_crypto_engine.py # CryptoEngine unit tests
│   ├── test_file_handler.py  # FileHandler unit tests
│   ├── test_db_logger.py     # SQLite logging unit tests
│   └── test_integration.py   # End-to-end integration & boundary tests
├── main.py                   # Desktop GUI application launcher
├── cli.py                    # Command-line interface for automation / testing
├── run_tests.py              # Automated test runner (24 unit & integration tests)
├── benchmark.py              # Performance throughput and KDF latency benchmarking
├── requirements.txt          # Package dependencies
└── README.md                 # User Manual and Technical Documentation
```

---

## 3. Installation and Setup

### Prerequisites
* **Python 3.8+** (Tested on Python 3.10 – 3.14 on Linux, Windows 10/11, and macOS).
* **Tkinter** (Included with standard Python installations on Windows/macOS; on Debian/Ubuntu Linux install via `sudo apt install python3-tk`).

### Step-by-Step Installation
1. Open a terminal / command prompt and navigate to the project directory:
   ```bash
   cd "file_encryption_system"
   ```

2. (Optional but recommended) Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # On Windows: venv\Scripts\activate
   ```

3. Install the required cryptographic dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 4. Usage Instructions

### A. Launching the Graphical User Interface (GUI)
Run the `main.py` entry point:
```bash
python3 main.py
```
* **To Encrypt:**
  1. Click **"Browse..."** and select any target file (`.txt`, `.pdf`, `.docx`, `.png`, `.jpg`, `.mp4`, etc.).
  2. Enter a secret passphrase in the **Passphrase** field (click "Show" to verify your typing).
  3. Click **"🔒 Encrypt File"**.
  4. The application generates an encrypted package appending `.enc` (e.g. `report.pdf.enc`).
  5. *Note:* The unencrypted original file remains on disk for safety.
* **To Decrypt:**
  1. Click **"Browse..."** and select the `.enc` file.
  2. Enter the identical passphrase used during encryption.
  3. Click **"🔓 Decrypt File"**.
  4. The system validates the HMAC authentication tag. If the password is correct and the file is untampered, the original document is restored with its native file extension.
* **To View Audit Logs:**
  * Click **"📋 View Audit History"** to display the SQLite audit dialog showing timestamps, operations, file paths, and outcome statuses.

### B. Using the Command-Line Interface (CLI)
The CLI allows headless automation, batch processing, and script grading:
```bash
# Encrypt a file
python3 cli.py encrypt document.pdf -p "MySecretPassword@2026"

# Decrypt an encrypted package
python3 cli.py decrypt document.pdf.enc -p "MySecretPassword@2026"

# View recent SQLite audit history
python3 cli.py history --limit 10
```

### C. Running the Automated Test Suite
To execute all 24 unit and integration tests:
```bash
python3 run_tests.py
```

### D. Running Benchmarks
To evaluate key derivation latency and file throughput on your host hardware:
```bash
python3 benchmark.py
```

---

## 5. Binary File Format Specification

The `.enc` package uses a 64-byte big-endian header and a 32-byte authentication tag:

```text
+-----------------------+--------------------+---------------------+
| Field Name            | Data Type          | Size in Bytes       |
+-----------------------+--------------------+---------------------+
| Magic Bytes           | 4s (ASCII "FED1")  | 4 Bytes             |
| Original File Size    | !Q (Unsigned Int64)| 8 Bytes             |
| Iteration Count       | !I (Unsigned Int32)| 4 Bytes (100,000)   |
| Salt                  | Raw Binary Bytes   | 16 Bytes            |
| Initialization Vector | Raw Binary Bytes   | 16 Bytes            |
| File Extension        | 16s (Padded String)| 16 Bytes (e.g. .pdf)|
+-----------------------+--------------------+---------------------+
| Ciphertext Payload    | AES-256-CBC Bytes  | Variable (Block=16) |
+-----------------------+--------------------+---------------------+
| HMAC Authentication   | HMAC-SHA256 Digest | 32 Bytes            |
+-----------------------+--------------------+---------------------+
```

---

## 6. Security and Privacy Guarantees
1. **Zero Password Persistence:** User passphrases and raw encryption keys exist strictly in volatile memory during processing and are never written to disk or logged.
2. **Constant-Time Verification:** Tag comparison utilizes `hmac.compare_digest` to prevent timing attacks.
3. **Atomic File Operations:** File output writes to a temporary file before atomic renaming, preventing truncation if an operation is interrupted.
4. **Air-Gapped Independence:** Zero external network calls or cloud dependencies.
