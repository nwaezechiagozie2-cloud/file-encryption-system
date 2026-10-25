#!/usr/bin/env python3
"""
Test Runner Script
==================
Discovers and executes all unit and integration tests for the
File Encryption and Decryption System.
"""

import unittest
import sys
import os

# Ensure project directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_all_tests():
    """Run all tests in the tests/ directory."""
    print("=" * 70)
    print("File Encryption & Decryption System - Automated Verification Suite")
    print("Testing AES-256-CBC, PBKDF2-HMAC-SHA256, HMAC Integrity, and SQLite")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="tests", pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print(f"Tests Run     : {result.testsRun}")
    print(f"Failures      : {len(result.failures)}")
    print(f"Errors        : {len(result.errors)}")
    print(f"Skipped       : {len(result.skipped)}")
    print("=" * 70)

    if result.wasSuccessful():
        print(">>> ALL TESTS PASSED SUCCESSFULLY! <<<")
        return 0
    else:
        print(">>> SOME TESTS FAILED! <<<")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
