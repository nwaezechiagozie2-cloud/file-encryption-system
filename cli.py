#!/usr/bin/env python3
"""
Command-Line Interface (CLI)
============================
Provides command-line execution of the File Encryption and Decryption System.
Supports single-file and batch multi-file operations.
"""

import sys
import os
import argparse
import getpass
from app.service import FileCryptoService
from app.db_logger import DBLogger


def main():
    parser = argparse.ArgumentParser(
        description="File Encryption and Decryption System (AES-256-CBC, PBKDF2, HMAC-SHA256)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Encrypt parser
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt one or more plaintext files")
    enc_parser.add_argument("files", nargs="+", help="Path(s) to plaintext file(s) to encrypt")
    enc_parser.add_argument("-p", "--password", help="Secret passphrase (will prompt if omitted)")
    enc_parser.add_argument("-o", "--output", help="Custom encrypted destination path (single file only)")
    enc_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing destination file(s)")

    # Decrypt parser
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt one or more encrypted .enc packages")
    dec_parser.add_argument("files", nargs="+", help="Path(s) to .enc package(s) to decrypt")
    dec_parser.add_argument("-p", "--password", help="Secret passphrase (will prompt if omitted)")
    dec_parser.add_argument("-o", "--output", help="Custom restored destination path (single file only)")
    dec_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing destination file(s)")

    # History parser
    hist_parser = subparsers.add_parser("history", help="View recent audit transactions from SQLite")
    hist_parser.add_argument("-n", "--limit", type=int, default=20, help="Number of records to show")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    service = FileCryptoService()

    if args.command == "encrypt":
        pwd = args.password or getpass.getpass("Enter encryption passphrase: ")
        if not pwd:
            print("[-] ERROR: Passphrase cannot be empty.", file=sys.stderr)
            sys.exit(1)

        if len(args.files) == 1:
            success, out_path, msg = service.encrypt_file(
                input_path=args.files[0],
                password=pwd,
                output_path=args.output,
                overwrite=args.force,
                progress_cb=lambda s: print(f"[*] {s}")
            )
            if success:
                print(f"[+] SUCCESS: {msg}")
                print(f"[+] Output: {out_path}")
            else:
                print(f"[-] ERROR: {msg}", file=sys.stderr)
                sys.exit(1)
        else:
            if args.output:
                print("[-] WARNING: -o/--output flag is ignored when encrypting multiple files in batch.", file=sys.stderr)

            print(f"[*] Starting batch encryption of {len(args.files)} files...")
            results = service.encrypt_batch(
                input_paths=args.files,
                password=pwd,
                overwrite=args.force,
                progress_cb=lambda idx, tot, p: print(f"[*] [{idx}/{tot}] Encrypting {os.path.basename(p)}...")
            )
            succeeded = [r for r in results if r[1]]
            failed = [r for r in results if not r[1]]

            print("-" * 60)
            for src, ok, out, msg in results:
                prefix = "[+]" if ok else "[-]"
                print(f"{prefix} {os.path.basename(src)}: {out if ok else msg}")
            print("-" * 60)
            print(f"[*] Batch summary: {len(succeeded)} succeeded, {len(failed)} failed.")
            if failed:
                sys.exit(1)

    elif args.command == "decrypt":
        pwd = args.password or getpass.getpass("Enter decryption passphrase: ")
        if not pwd:
            print("[-] ERROR: Passphrase cannot be empty.", file=sys.stderr)
            sys.exit(1)

        if len(args.files) == 1:
            success, out_path, msg = service.decrypt_file(
                encrypted_path=args.files[0],
                password=pwd,
                output_path=args.output,
                overwrite=args.force,
                progress_cb=lambda s: print(f"[*] {s}")
            )
            if success:
                print(f"[+] SUCCESS: {msg}")
                print(f"[+] Restored: {out_path}")
            else:
                print(f"[-] ERROR: {msg}", file=sys.stderr)
                sys.exit(1)
        else:
            if args.output:
                print("[-] WARNING: -o/--output flag is ignored when decrypting multiple files in batch.", file=sys.stderr)

            print(f"[*] Starting batch decryption of {len(args.files)} files...")
            results = service.decrypt_batch(
                encrypted_paths=args.files,
                password=pwd,
                overwrite=args.force,
                progress_cb=lambda idx, tot, p: print(f"[*] [{idx}/{tot}] Decrypting {os.path.basename(p)}...")
            )
            succeeded = [r for r in results if r[1]]
            failed = [r for r in results if not r[1]]

            print("-" * 60)
            for src, ok, out, msg in results:
                prefix = "[+]" if ok else "[-]"
                print(f"{prefix} {os.path.basename(src)}: {out if ok else msg}")
            print("-" * 60)
            print(f"[*] Batch summary: {len(succeeded)} succeeded, {len(failed)} failed.")
            if failed:
                sys.exit(1)

    elif args.command == "history":
        records = service.logger.fetch_history(limit=args.limit)
        if not records:
            print("[*] No activity records found in local_audit.db.")
            return

        print(f"{'ID':<6} {'TIMESTAMP (UTC)':<22} {'OPERATION':<14} {'FILE':<30} {'STATUS'}")
        print("-" * 90)
        for r in records:
            fname = os.path.basename(r["file_path"])
            print(f"{r['log_id']:<6} {r['timestamp']:<22} {r['operation']:<14} {fname:<30} {r['status_message']}")


if __name__ == "__main__":
    main()
