# File Encryption and Decryption System

**Department of Computer Science, University of Nigeria, Nsukka (UNN)**  
**B.Sc. Final Year Project Implementation**

---

## 1. Overview
The **File Encryption and Decryption System** is an offline, desktop cryptographic software utility engineered in Python. It provides authenticated, high-performance file protection using:
* **AES-256-CBC:** Symmetric block cipher operating with a 256-bit key and standard PKCS#7 padding (with pure-Python RFC 5652 fallback).
* **PBKDF2-HMAC-SHA256:** Password-based Key Derivation Function with a 16-byte random salt and 100,000 iterations to derive a 256-bit AES encryption key and a 256-bit MAC key.
* **HMAC-SHA256 (Encrypt-then-MAC):** Cryptographic authentication tag covering both metadata and ciphertext, ensuring tampering or incorrect passwords are detected in constant time *before* any plaintext is released.
* **Preserved File Extension Header:** Packed binary envelope format (`FED1`) that preserves the original file extension so renamed `.enc` packages restore with their native file type.
* **Native Desktop File Chooser & Multi-File Batch Selection:** Automatically launches your laptop's native desktop file manager (GNOME Files via Zenity, KDE via kdialog, Windows Explorer, or macOS Finder) supporting multi-file selection (`Ctrl`/`Shift` click) and batch processing.
* **Asynchronous Desktop GUI:** Built using Python's `tkinter` and `ttk` with background worker threading to keep the interface responsive during heavy cryptographic operations.
* **Local SQLite Audit Logger:** Maintains an automated, thread-safe operational history (`local_audit.db`) of all encryption and decryption events.

---

## 2. Project Directory Structure

```text
file_encryption_system/
├── app/
│   ├── __init__.py           # Package exports
│   ├── crypto_engine.py      # AES-256-CBC, PBKDF2, PKCS7, HMAC-SHA256
│   ├── file_handler.py       # Binary I/O, !4sQI16s16s16s header, atomic writes
│   ├── db_logger.py          # SQLite local_audit.db connection & history
│   ├── service.py            # High-level crypto controller & batch pipeline
│   └── gui.py                # Tkinter desktop GUI, native file picker & modal
├── tests/
│   ├── __init__.py
│   ├── test_crypto_engine.py # CryptoEngine unit tests
│   ├── test_file_handler.py  # FileHandler unit tests
│   ├── test_db_logger.py     # SQLite logging unit tests
│   └── test_integration.py   # End-to-end integration, batch & boundary tests
├── main.py                   # Desktop GUI application launcher
├── cli.py                    # Command-line interface for automation & batch processing
├── run_tests.py              # Automated test runner (25 unit & integration tests)
├── benchmark.py              # Performance throughput and KDF latency benchmarking
├── requirements.txt          # Package dependencies (pycryptodome)
├── SOFTWARE_BUGS_AND_FIXES.txt # Comprehensive software audit & bugfix report
└── README.md                 # User Manual and Technical Documentation
```

---

## 3. OS-Specific Installation & Setup Guide

The application is written in standard Python 3 and runs cross-platform on **Windows**, **Linux**, and **macOS**. Follow the instructions below for your specific operating system:

---

### A. Microsoft Windows (Windows 10 / 11)

#### 1. Install Python
1. Download Python 3.10+ from the official website: [python.org/downloads](https://www.python.org/downloads/).
2. Run the installer. **IMPORTANT:** Ensure you check the box that says:
   `☑ Add python.exe to PATH` (at the bottom of the installer window).
3. Complete the installation.

#### 2. Open Command Prompt or PowerShell
Press `Win + R`, type `cmd` (or `powershell`), and press Enter. Verify your installation:
```cmd
python --version
pip --version
```

#### 3. Clone or Extract the Project
Navigate to the directory containing `file_encryption_system`:
```cmd
cd path\to\file_encryption_system
```

#### 4. (Optional but Recommended) Setup a Virtual Environment
```cmd
python -m venv venv
venv\Scripts\activate
```

#### 5. Install Dependencies
```cmd
pip install -r requirements.txt
```

#### 6. Run the Application
* **To launch the Graphical User Interface (GUI):**
  ```cmd
  python main.py
  ```
  *(You can also simply double-click `main.py` in Windows Explorer).*
* **To use the Command-Line Interface (CLI):**
  ```cmd
  python cli.py --help
  ```

> **Windows Note:** Tkinter is bundled natively with the official Python Windows installer. File dialogues use the native Windows File Explorer interface.

---

### B. Linux (Ubuntu / Debian / Linux Mint / Pop!_OS)

#### 1. Install Python, Pip, Tkinter, and Native Desktop Portal
On Debian/Ubuntu-based distributions, Python is preinstalled, but `python3-tk` (Tkinter) and `python3-venv` must be installed via APT:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv python3-tk zenity -y
```
*(Installing `zenity` ensures the application opens your modern GNOME/GTK file manager with multi-file selection support).*

#### 2. Navigate to Project Directory
```bash
cd /path/to/file_encryption_system
```

#### 3. (Optional) Setup a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 5. Run the Application
* **GUI:**
  ```bash
  python3 main.py
  ```
* **CLI:**
  ```bash
  python3 cli.py --help
  ```

---

### C. Linux (Fedora / RHEL / CentOS / Rocky Linux / AlmaLinux)

#### 1. Install Packages via DNF
```bash
sudo dnf install python3 python3-pip python3-tkinter zenity -y
```

#### 2. Navigate to Project Directory
```bash
cd /path/to/file_encryption_system
```

#### 3. Setup Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 4. Run the Application
```bash
python3 main.py
```

---

### D. Linux (Arch Linux / Manjaro)

#### 1. Install Packages via Pacman
```bash
sudo pacman -S python python-pip tk zenity
```

#### 2. Navigate to Project Directory and Install Requirements
```bash
cd /path/to/file_encryption_system
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Run the Application
```bash
python3 main.py
```

---

### E. Apple macOS (macOS 12 Monterey, 13 Ventura, 14 Sonoma, 15+)

#### 1. Install Python
* **Option 1 (Official Installer - Recommended):** Download and install Python 3.11+ from [python.org/downloads/macos](https://www.python.org/downloads/macos/). This installer includes Tcl/Tk Aqua bindings natively.
* **Option 2 (Homebrew):**
  ```bash
  brew install python python-tk
  ```

#### 2. Navigate to Project Directory
Open the Terminal app (`Cmd + Space`, type `Terminal`) and navigate to the project folder:
```bash
cd /path/to/file_encryption_system
```

#### 3. Setup Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 4. Run the Application
* **GUI:**
  ```bash
  python3 main.py
  ```
* **CLI:**
  ```bash
  python3 cli.py --help
  ```

> **macOS Note:** Runs natively on both Apple Silicon (M1/M2/M3/M4) and Intel architectures. File dialogs use the native macOS Finder picker.

---

## 4. Usage Instructions

### A. Graphical User Interface (GUI)
Run:
```bash
python3 main.py
```

1. **Selecting Files (Single or Multiple):**
   * Click **Browse...** to launch your native desktop file manager.
   * To select multiple files, hold `Ctrl` (or `Cmd` on macOS) or `Shift`, or drag a selection box across your files.
   * The application displays the total file count and combined size (e.g., `Selected: 3 files | Total Size: 14.8 MB`).
   * When multiple files are selected, a **📄 View List** button appears allowing you to inspect individual files and remove any unwanted items before proceeding.
   * Click **Clear** at any time to reset your file selection.
2. **Entering Passphrase:**
   * Enter your secret passphrase into the passphrase box.
   * Click the **Show** checkbox to toggle password masking.
3. **Encrypting:**
   * Click **🔒 Encrypt File** (or **🔒 Encrypt N Files**).
   * Files are encrypted in the background without UI freezing.
   * Each target file produces a `.enc` package alongside the original file.
   * *Safety Note:* Your unencrypted original files remain on disk.
4. **Decrypting:**
   * Click **Browse...** and select one or more `.enc` packages.
   * Enter the exact passphrase and click **🔓 Decrypt File(s)**.
   * The HMAC tag is verified in constant time. If valid, the original files are restored with their authentic extensions.
5. **Viewing Audit History:**
   * Click **📋 View Audit History** to open the SQLite history modal, displaying UTC timestamps, operations, file paths, and success/failure statuses.

---

### B. Command-Line Interface (CLI)

The CLI supports both single-file and multi-file batch execution:

#### Single File Operations
```bash
# Encrypt a single file (will securely prompt for password with getpass)
python3 cli.py encrypt document.pdf

# Encrypt with explicit passphrase and custom output
python3 cli.py encrypt document.pdf -p "MySecretPassphrase123!" -o secure_doc.enc

# Decrypt a file
python3 cli.py decrypt document.pdf.enc -p "MySecretPassphrase123!"
```

#### Batch Multi-File Operations
```bash
# Encrypt multiple files at once
python3 cli.py encrypt doc1.pdf notes.txt presentation.pptx -p "BatchPass123!"

# Decrypt multiple packages at once
python3 cli.py decrypt doc1.pdf.enc notes.txt.enc presentation.pptx.enc -p "BatchPass123!"

# Overwrite existing files if they already exist
python3 cli.py encrypt *.docx -p "BatchPass123!" --force
```

#### View Audit Trail
```bash
python3 cli.py history --limit 20
```

---

## 5. Automated Verification & Benchmarking

### Run Test Suite (25 Tests)
To run the automated verification suite covering AES-256-CBC roundtrips, PBKDF2 determinism, PKCS#7 boundary sizes (0B, 1B, 15B, 16B, 17B), bit-flip tamper rejection, wrong password rejection, extension restoration, and SQLite concurrency:
```bash
python3 run_tests.py
```
*Expected Result:* `Ran 25 tests ... OK >>> ALL TESTS PASSED SUCCESSFULLY! <<<`

### Run Performance Benchmarks
To evaluate key derivation latency, encryption throughput, and decryption throughput on your hardware:
```bash
python3 benchmark.py
```

---

## 6. Binary Header Specification (`FED1`)

The `.enc` package utilizes a rigid 64-byte big-endian binary header (`!4sQI16s16s16s`) followed by the ciphertext and a concluding 32-byte HMAC tag:

```text
+-----------------------+--------------------+---------------------+
| Field Name            | Data Type          | Size in Bytes       |
+-----------------------+--------------------+---------------------+
| Magic Bytes           | 4s (ASCII "FED1")  | 4 Bytes             |
| Original File Size    | !Q (Unsigned Int64)| 8 Bytes             |
| Iteration Count       | !I (Unsigned Int32)| 4 Bytes (100,000)   |
| Salt                  | Raw Binary Bytes   | 16 Bytes            |
| Initialization Vector | Raw Binary Bytes   | 16 Bytes            |
| Original Extension    | 16s (Padded String)| 16 Bytes (e.g. .pdf)|
+-----------------------+--------------------+---------------------+
| Ciphertext Payload    | AES-256-CBC Bytes  | Variable (Block=16) |
+-----------------------+--------------------+---------------------+
| HMAC Authentication   | HMAC-SHA256 Digest | 32 Bytes            |
+-----------------------+--------------------+---------------------+
```

---

## 7. Security Guarantees
1. **Zero Secret Persistence:** Passphrases and derived keys exist only in volatile RAM during active cryptographic routines and are immediately discarded.
2. **Defeat of Brute-Force & Rainbow Tables:** 100,000 rounds of PBKDF2-HMAC-SHA256 with a unique 16-byte random salt per file.
3. **Tamper Rejection (Encrypt-then-MAC):** HMAC-SHA256 authentication tag verified in constant time (`hmac.compare_digest`) *before* unpadding, neutralizing padding oracle attacks.
4. **Atomic Disk Operations:** Writes to temporary files and commits with `os.fsync()` and `os.replace()` to prevent partial corruption on unexpected system shutdown.
5. **No Network Footprint:** Runs completely air-gapped without telemetry or cloud connections.
