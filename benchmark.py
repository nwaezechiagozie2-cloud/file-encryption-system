#!/usr/bin/env python3
"""
Benchmark & Performance Evaluation Script
=========================================
Measures:
- PBKDF2-HMAC-SHA256 derivation latency across iteration work factors
- Encryption & Decryption throughput (MB/s) across file sizes (1 KB, 100 KB, 1 MB, 10 MB)
- CPU and platform hardware specifications
Generates structured tables ready for Chapter Four of the project report.
"""

import time
import os
import sys
import platform
import tempfile
import hashlib
from app.crypto_engine import CryptoEngine
from app.service import FileCryptoService


def benchmark_kdf():
    """Benchmark PBKDF2-HMAC-SHA256 key derivation across iteration counts."""
    print("\n" + "=" * 75)
    print("1. PBKDF2-HMAC-SHA256 Key Derivation Latency Evaluation")
    print("=" * 75)
    print(f"{'Iteration Count':<20} {'Average Time (ms)':<22} {'Security Level / Guidance'}")
    print("-" * 75)

    iterations_list = [10_000, 50_000, 100_000, 200_000]
    salt = CryptoEngine.generate_salt()
    pwd = "BenchmarkPassphrase@2026"

    for iters in iterations_list:
        runs = 5
        start = time.perf_counter()
        for _ in range(runs):
            CryptoEngine.derive_keys(pwd, salt, iterations=iters)
        elapsed_ms = ((time.perf_counter() - start) / runs) * 1000

        guidance = "Legacy / Low" if iters < 50_000 else ("NIST Recommended (Current)" if iters == 100_000 else "High Security")
        print(f"{iters:<20} {elapsed_ms:<22.2f} {guidance}")


def benchmark_file_throughput():
    """Benchmark end-to-end file throughput across increasing payload sizes."""
    print("\n" + "=" * 75)
    print("2. End-to-End File Encryption and Decryption Throughput")
    print("=" * 75)
    print(f"{'File Size':<14} {'Enc Time (ms)':<16} {'Enc Rate (MB/s)':<18} {'Dec Time (ms)':<16} {'Dec Rate (MB/s)'}")
    print("-" * 75)

    test_sizes = [
        ("1 KB", 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
        ("10 MB", 10 * 1024 * 1024),
    ]

    service = FileCryptoService()
    pwd = "BenchmarkPassword@2026"

    with tempfile.TemporaryDirectory() as temp_dir:
        for label, size_bytes in test_sizes:
            data = os.urandom(size_bytes)
            test_file = os.path.join(temp_dir, f"bench_{label.replace(' ', '')}.bin")
            with open(test_file, "wb") as f:
                f.write(data)

            # Encryption benchmark
            t0 = time.perf_counter()
            success_enc, enc_path, _ = service.encrypt_file(test_file, pwd, overwrite=True)
            enc_time = time.perf_counter() - t0
            enc_rate = (size_bytes / (1024 * 1024)) / enc_time if enc_time > 0 else 0

            # Decryption benchmark
            rest_file = os.path.join(temp_dir, f"bench_{label.replace(' ', '')}.restored")
            t1 = time.perf_counter()
            success_dec, _, _ = service.decrypt_file(enc_path, pwd, output_path=rest_file, overwrite=True)
            dec_time = time.perf_counter() - t1
            dec_rate = (size_bytes / (1024 * 1024)) / dec_time if dec_time > 0 else 0

            # Verify integrity
            with open(rest_file, "rb") as f:
                restored = f.read()
            assert hashlib.sha256(data).digest() == hashlib.sha256(restored).digest(), "Integrity failed!"

            print(f"{label:<14} {enc_time*1000:<16.2f} {enc_rate:<18.2f} {dec_time*1000:<16.2f} {dec_rate:.2f}")


def print_system_specs():
    """Print system hardware environment details for academic reproducibility."""
    print("\n" + "=" * 75)
    print("3. Test Hardware & Software Environment")
    print("=" * 75)
    print(f"Platform / OS       : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Version      : {platform.python_version()} ({platform.python_implementation()})")
    print(f"Cryptographic Engine: PyCryptodome (AES-256-CBC, PKCS7, CSPRNG)")
    print(f"Hash / MAC Engine   : Python hashlib (PBKDF2-HMAC-SHA256) & hmac (HMAC-SHA256)")
    print(f"Audit Store         : SQLite 3 (local_audit.db)")
    print("=" * 75)


if __name__ == "__main__":
    print_system_specs()
    benchmark_kdf()
    benchmark_file_throughput()
