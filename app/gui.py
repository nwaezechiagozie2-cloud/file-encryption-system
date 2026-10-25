"""
AppGUI Module
=============
Provides the Graphical User Interface (GUI) built with Python's Tkinter and ttk.
Features:
- Responsive asynchronous worker threading (prevents window freezing)
- Native OS file manager integration (GNOME Zenity / KDE kdialog with Tkinter fallback)
- Single and multiple file selection with batch processing
- Masked password input with show/hide toggle
- Overwrite confirmation prompts
- Live status and progress bar updates
- Interactive Selected Files list modal with item removal
- Interactive Activity History log viewer modal (SQLite: local_audit.db)
"""

import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, List
from .service import FileCryptoService
from .db_logger import DBLogger


class AppGUI:
    """Main Application GUI window supporting single and multiple file processing."""

    def __init__(self, root: tk.Tk, service: Optional[FileCryptoService] = None):
        self.root = root
        self.root.title("File Encryption & Decryption System")
        self.root.geometry("660x520")
        self.root.minsize(600, 460)

        self.service = service or FileCryptoService()
        self._is_busy = False
        self._selected_files: List[str] = []

        self._configure_styles()
        self._create_widgets()

    def _configure_styles(self):
        """Set up modern styling and palette."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Color palette
        self.COLOR_BG = "#F4F6F9"
        self.COLOR_CARD = "#FFFFFF"
        self.COLOR_PRIMARY = "#1A73E8"
        self.COLOR_SUCCESS = "#2E7D32"
        self.COLOR_TEXT = "#202124"
        self.COLOR_MUTED = "#5F6368"

        self.root.configure(bg=self.COLOR_BG)

        style.configure("TFrame", background=self.COLOR_BG)
        style.configure("Card.TFrame", background=self.COLOR_CARD, relief="ridge", borderwidth=1)
        style.configure("TLabel", background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=("Helvetica", 10))
        style.configure("Card.TLabel", background=self.COLOR_CARD, foreground=self.COLOR_TEXT, font=("Helvetica", 10))
        style.configure("Header.TLabel", background=self.COLOR_BG, foreground=self.COLOR_PRIMARY, font=("Helvetica", 15, "bold"))
        style.configure("Subtitle.TLabel", background=self.COLOR_BG, foreground=self.COLOR_MUTED, font=("Helvetica", 9))
        style.configure("Status.TLabel", background=self.COLOR_BG, foreground=self.COLOR_PRIMARY, font=("Helvetica", 9, "italic"))

        style.configure("Primary.TButton", font=("Helvetica", 10, "bold"), padding=6)
        style.configure("Secondary.TButton", font=("Helvetica", 10), padding=6)

    def _create_widgets(self):
        """Build all user interface components."""
        main_container = ttk.Frame(self.root, padding=16)
        main_container.pack(fill=tk.BOTH, expand=True)

        # 1. Header Section
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 12))

        title_lbl = ttk.Label(header_frame, text="🔒 File Encryption & Decryption System", style="Header.TLabel")
        title_lbl.pack(anchor=tk.W)

        subtitle_lbl = ttk.Label(
            header_frame,
            text="Authenticated AES-256-CBC with PBKDF2 Key Derivation & Batch Processing",
            style="Subtitle.TLabel"
        )
        subtitle_lbl.pack(anchor=tk.W, pady=(2, 0))

        # 2. File Selection Card
        file_card = ttk.Frame(main_container, style="Card.TFrame", padding=12)
        file_card.pack(fill=tk.X, pady=(0, 12))

        file_hdr_frame = ttk.Frame(file_card, style="Card.TFrame")
        file_hdr_frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(file_hdr_frame, text="Target File(s):", font=("Helvetica", 10, "bold"), style="Card.TLabel").pack(side=tk.LEFT)

        file_input_frame = ttk.Frame(file_card, style="Card.TFrame")
        file_input_frame.pack(fill=tk.X, pady=(4, 6))

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_input_frame, textvariable=self.file_path_var, font=("Helvetica", 10))
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.browse_btn = ttk.Button(file_input_frame, text="Browse...", command=self._on_browse_file)
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.clear_btn = ttk.Button(file_input_frame, text="Clear", command=self._on_clear_file)
        self.clear_btn.pack(side=tk.LEFT)

        file_info_frame = ttk.Frame(file_card, style="Card.TFrame")
        file_info_frame.pack(fill=tk.X, pady=(2, 0))

        self.file_info_lbl = ttk.Label(
            file_info_frame,
            text="Select one or more plaintext files to encrypt, or .enc files to decrypt.",
            style="Card.TLabel",
            foreground=self.COLOR_MUTED
        )
        self.file_info_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.view_files_btn = ttk.Button(
            file_info_frame,
            text="📄 View List",
            command=self._on_view_selected_files_click
        )
        # Initially not packed until multiple files are selected

        # 3. Password Card
        pass_card = ttk.Frame(main_container, style="Card.TFrame", padding=12)
        pass_card.pack(fill=tk.X, pady=(0, 14))

        ttk.Label(pass_card, text="Secret Passphrase:", font=("Helvetica", 10, "bold"), style="Card.TLabel").pack(anchor=tk.W)

        pass_input_frame = ttk.Frame(pass_card, style="Card.TFrame")
        pass_input_frame.pack(fill=tk.X, pady=(6, 4))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pass_input_frame, textvariable=self.password_var, show="*", font=("Helvetica", 10))
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.show_pass_var = tk.BooleanVar(value=False)
        self.toggle_pass_btn = ttk.Checkbutton(
            pass_input_frame, text="Show", variable=self.show_pass_var, command=self._on_toggle_show_pass
        )
        self.toggle_pass_btn.pack(side=tk.RIGHT)

        ttk.Label(
            pass_card,
            text="Tip: Your passphrase is never stored. PBKDF2 derives a 256-bit AES key and a 256-bit MAC key using 100,000 rounds.",
            style="Card.TLabel",
            foreground=self.COLOR_MUTED
        ).pack(anchor=tk.W)

        # 4. Action Buttons
        btn_frame = ttk.Frame(main_container)
        btn_frame.pack(fill=tk.X, pady=(0, 14))

        self.encrypt_btn = ttk.Button(
            btn_frame,
            text="🔒 Encrypt File",
            style="Primary.TButton",
            command=self._on_encrypt_click
        )
        self.encrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.decrypt_btn = ttk.Button(
            btn_frame,
            text="🔓 Decrypt File",
            style="Primary.TButton",
            command=self._on_decrypt_click
        )
        self.decrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        self.history_btn = ttk.Button(
            btn_frame,
            text="📋 View Audit History",
            style="Secondary.TButton",
            command=self._on_view_history_click
        )
        self.history_btn.pack(side=tk.RIGHT, padx=(6, 0))

        # 5. Progress and Status Section
        status_frame = ttk.Frame(main_container)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(6, 0))

        self.progress_bar = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress_bar.pack(fill=tk.X, pady=(0, 4))

        self.status_var = tk.StringVar(value="System Ready.")
        self.status_lbl = ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel")
        self.status_lbl.pack(anchor=tk.W)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Return human-readable file size string."""
        if size_bytes < 1024:
            return f"{size_bytes} Bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.2f} MB"

    def _open_native_file_dialog(self, title: str = "Select Files") -> List[str]:
        """
        Open the laptop's native desktop file manager / file chooser supporting multiple selection.
        Uses Zenity on GNOME/GTK Linux, kdialog on KDE, or falls back to
        Tkinter's standard dialog on Windows/macOS/fallback systems.
        """
        initial_dir = os.path.expanduser("~")
        if self._selected_files and os.path.exists(self._selected_files[0]):
            initial_dir = os.path.dirname(os.path.abspath(self._selected_files[0]))

        # 1. On Linux: try desktop native tools (Zenity for GNOME/GTK, kdialog for KDE)
        if sys.platform.startswith("linux") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            if shutil.which("zenity"):
                cmd = [
                    "zenity",
                    "--file-selection",
                    f"--title={title}",
                    f"--filename={initial_dir}/",
                    "--multiple",
                    "--separator=|"
                ]
                try:
                    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if res.returncode == 0:
                        raw = res.stdout.strip()
                        if raw:
                            paths = [p.strip() for p in raw.split("|") if p.strip() and os.path.exists(p.strip())]
                            return paths
                    return []
                except Exception:
                    pass

            if shutil.which("kdialog"):
                cmd = ["kdialog", "--getopenfilename", initial_dir, "--multiple", "--separate-output"]
                try:
                    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if res.returncode == 0:
                        raw = res.stdout.strip()
                        if raw:
                            paths = [p.strip() for p in raw.splitlines() if p.strip() and os.path.exists(p.strip())]
                            return paths
                    return []
                except Exception:
                    pass

        # 2. Windows, macOS, or fallback
        selected = filedialog.askopenfilenames(
            title=title,
            initialdir=initial_dir,
            filetypes=[("All Files", "*.*"), ("Encrypted Files (*.enc)", "*.enc")]
        )
        return list(selected) if selected else []

    def _on_browse_file(self):
        """Open native OS file chooser dialog supporting multiple file selection."""
        selected_paths = self._open_native_file_dialog(
            title="Select File(s) for Encryption or Decryption"
        )
        if selected_paths:
            self._selected_files = selected_paths
            self._update_file_selection_display()

    def _on_clear_file(self):
        """Clear current file selection."""
        self._selected_files = []
        self.file_path_var.set("")
        self._update_file_selection_display()

    def _update_file_selection_display(self):
        """Update GUI elements reflecting the active file selection."""
        count = len(self._selected_files)

        if count == 0:
            self.file_path_var.set("")
            self.file_info_lbl.config(
                text="Select one or more plaintext files to encrypt, or .enc files to decrypt."
            )
            self.encrypt_btn.config(text="🔒 Encrypt File")
            self.decrypt_btn.config(text="🔓 Decrypt File")
            self.view_files_btn.pack_forget()
            return

        if count == 1:
            f = self._selected_files[0]
            self.file_path_var.set(f)
            self.view_files_btn.pack_forget()
            self.encrypt_btn.config(text="🔒 Encrypt File")
            self.decrypt_btn.config(text="🔓 Decrypt File")
            try:
                size_str = self._format_size(os.path.getsize(f))
                is_enc = f.lower().endswith(".enc")
                kind = "Encrypted Package (.enc)" if is_enc else f"Plaintext File ({os.path.splitext(f)[1] or 'binary'})"
                self.file_info_lbl.config(text=f"Selected: {kind} | Size: {size_str}")
            except Exception:
                self.file_info_lbl.config(text=f"Selected: {f}")
        else:
            # Multiple files selected
            total_bytes = sum(os.path.getsize(f) for f in self._selected_files if os.path.exists(f))
            total_str = self._format_size(total_bytes)
            preview = ", ".join(os.path.basename(f) for f in self._selected_files[:2])
            if count > 2:
                preview += f", +{count - 2} more"

            self.file_path_var.set(f"[{count} files selected] {preview}")
            self.file_info_lbl.config(text=f"Selected: {count} files | Total Size: {total_str}")
            self.encrypt_btn.config(text=f"🔒 Encrypt {count} Files")
            self.decrypt_btn.config(text=f"🔓 Decrypt {count} Files")
            self.view_files_btn.config(text=f"📄 View List ({count})")
            self.view_files_btn.pack(side=tk.RIGHT, padx=(6, 0))

    def _on_view_selected_files_click(self):
        """Open a modal dialog showing all currently selected files."""
        if not self._selected_files:
            return

        modal = tk.Toplevel(self.root)
        modal.title(f"Selected Files ({len(self._selected_files)})")
        modal.geometry("560x360")
        modal.minsize(460, 260)
        modal.transient(self.root)
        modal.grab_set()

        list_frame = ttk.Frame(modal, padding=12)
        list_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            list_frame,
            text=f"Currently selected {len(self._selected_files)} files:",
            font=("Helvetica", 10, "bold")
        ).pack(anchor=tk.W, pady=(0, 6))

        scroll = ttk.Scrollbar(list_frame)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        file_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scroll.set,
            font=("Courier", 9),
            selectmode=tk.EXTENDED
        )
        file_listbox.pack(fill=tk.BOTH, expand=True)
        scroll.config(command=file_listbox.yview)

        for f in self._selected_files:
            sz = ""
            try:
                sz = f" ({self._format_size(os.path.getsize(f))})"
            except Exception:
                pass
            file_listbox.insert(tk.END, f"{os.path.basename(f)}{sz}  —  {f}")

        btn_row = ttk.Frame(modal, padding=(12, 8))
        btn_row.pack(fill=tk.X, side=tk.BOTTOM)

        def remove_selected():
            indices = list(file_listbox.curselection())
            if not indices:
                return
            for idx in reversed(indices):
                if 0 <= idx < len(self._selected_files):
                    self._selected_files.pop(idx)
                    file_listbox.delete(idx)
            self._update_file_selection_display()
            modal.title(f"Selected Files ({len(self._selected_files)})")
            if not self._selected_files:
                modal.destroy()

        ttk.Button(btn_row, text="Remove Selected", command=remove_selected).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Close", command=modal.destroy).pack(side=tk.RIGHT)

    def _get_target_files(self) -> List[str]:
        """Return list of valid, existing file paths from selection or text input."""
        if self._selected_files:
            valid = [f for f in self._selected_files if os.path.exists(f)]
            if valid:
                return valid

        # Fallback to direct text box entry
        manual = self.file_path_var.get().strip()
        if manual and os.path.exists(manual):
            return [manual]
        return []

    def _on_toggle_show_pass(self):
        """Toggle mask character in passphrase field."""
        if self.show_pass_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _set_busy(self, is_busy: bool, message: str = ""):
        """Update interface busy state and progress bar."""
        self._is_busy = is_busy
        state = tk.DISABLED if is_busy else tk.NORMAL

        self.browse_btn.config(state=state)
        self.clear_btn.config(state=state)
        self.encrypt_btn.config(state=state)
        self.decrypt_btn.config(state=state)
        self.history_btn.config(state=state)
        self.file_entry.config(state=state)
        self.password_entry.config(state=state)
        self.view_files_btn.config(state=state)

        if is_busy:
            self.progress_bar.start(10)
        else:
            self.progress_bar.stop()

        if message:
            self.status_var.set(message)

    def _on_encrypt_click(self):
        """Handler for Encrypt File(s) button."""
        targets = self._get_target_files()
        password = self.password_var.get()

        if not targets:
            messagebox.showwarning("File Required", "Please select at least one file to encrypt.")
            return
        if not password:
            messagebox.showwarning("Passphrase Required", "Please enter a passphrase.")
            return

        total = len(targets)
        # Check overwrite
        existing = [f + ".enc" for f in targets if os.path.exists(f + ".enc")]
        overwrite = False
        if existing:
            if len(existing) == 1:
                confirm = messagebox.askyesno(
                    "File Exists",
                    f"The encrypted file:\n'{existing[0]}'\nalready exists. Do you want to overwrite it?"
                )
            else:
                names = "\n".join(f"• {os.path.basename(e)}" for e in existing[:5])
                if len(existing) > 5:
                    names += f"\n...and {len(existing) - 5} more"
                confirm = messagebox.askyesno(
                    "Overwrite Existing Files?",
                    f"{len(existing)} encrypted file(s) already exist:\n\n{names}\n\nDo you want to overwrite them?"
                )
            if not confirm:
                return
            overwrite = True

        self._set_busy(True, f"Starting encryption of {total} file(s)...")

        def worker():
            def on_progress(idx, tot, path):
                msg = f"Encrypting [{idx}/{tot}]: {os.path.basename(path)}..."
                self.root.after(0, lambda: self.status_var.set(msg))

            results = self.service.encrypt_batch(
                input_paths=targets,
                password=password,
                overwrite=overwrite,
                progress_cb=on_progress
            )
            self.root.after(0, lambda: self._on_batch_encrypt_finished(results))

        threading.Thread(target=worker, daemon=True).start()

    def _on_batch_encrypt_finished(self, results: list):
        """Called on main thread when encryption completes."""
        self._set_busy(False, "Ready.")
        total = len(results)
        succeeded = [r for r in results if r[1]]
        failed = [r for r in results if not r[1]]

        if total == 1:
            src, success, out_path, msg = results[0]
            if success:
                messagebox.showinfo(
                    "Encryption Successful",
                    f"File encrypted successfully!\n\n"
                    f"Saved to:\n{out_path}\n\n"
                    f"Important: The original unencrypted file remains on your disk. "
                    f"Remember your passphrase—there is no backdoor or recovery mechanism."
                )
                self.status_var.set(f"Encrypted file saved to: {os.path.basename(out_path)}")
            else:
                messagebox.showerror("Encryption Error", msg)
                self.status_var.set("Encryption failed.")
        else:
            if not failed:
                messagebox.showinfo(
                    "Batch Encryption Complete",
                    f"All {total} files were successfully encrypted!\n\n"
                    f"Encrypted packages (.enc) have been saved alongside each original file.\n\n"
                    f"Note: Unencrypted source files remain untouched."
                )
                self.status_var.set(f"Successfully encrypted {total} files.")
            else:
                fail_details = "\n".join(f"• {os.path.basename(r[0])}: {r[3]}" for r in failed[:5])
                if len(failed) > 5:
                    fail_details += f"\n...and {len(failed) - 5} more"
                messagebox.showwarning(
                    "Batch Encryption Finished with Errors",
                    f"Processed {total} files:\n- {len(succeeded)} succeeded\n- {len(failed)} failed\n\nErrors:\n{fail_details}"
                )
                self.status_var.set(f"Encryption completed with {len(failed)} error(s).")

    def _on_decrypt_click(self):
        """Handler for Decrypt File(s) button."""
        targets = self._get_target_files()
        password = self.password_var.get()

        if not targets:
            messagebox.showwarning("File Required", "Please select at least one file to decrypt.")
            return
        if not password:
            messagebox.showwarning("Passphrase Required", "Please enter the passphrase.")
            return

        total = len(targets)
        non_enc = [f for f in targets if not f.lower().endswith(".enc")]
        if non_enc:
            msg = (
                f"{len(non_enc)} of the selected files do not end in '.enc'.\n\n"
                f"Attempt authenticated decryption anyway?"
            )
            if not messagebox.askyesno("Confirm Decryption", msg):
                return

        self._set_busy(True, f"Starting decryption of {total} file(s)...")

        def worker():
            def on_progress(idx, tot, path):
                msg = f"Decrypting [{idx}/{tot}]: {os.path.basename(path)}..."
                self.root.after(0, lambda: self.status_var.set(msg))

            results = self.service.decrypt_batch(
                encrypted_paths=targets,
                password=password,
                overwrite=True,
                progress_cb=on_progress
            )
            self.root.after(0, lambda: self._on_batch_decrypt_finished(results))

        threading.Thread(target=worker, daemon=True).start()

    def _on_batch_decrypt_finished(self, results: list):
        """Called on main thread when decryption completes."""
        self._set_busy(False, "Ready.")
        total = len(results)
        succeeded = [r for r in results if r[1]]
        failed = [r for r in results if not r[1]]

        if total == 1:
            src, success, out_path, msg = results[0]
            if success:
                messagebox.showinfo(
                    "Decryption Successful",
                    f"File authenticated and decrypted successfully!\n\n"
                    f"Restored to:\n{out_path}\n\n"
                    f"Integrity check passed: The cryptographic authentication tag was verified."
                )
                self.status_var.set(f"Restored file: {os.path.basename(out_path)}")
            else:
                messagebox.showerror("Decryption Failed", msg)
                self.status_var.set("Decryption failed.")
        else:
            if not failed:
                messagebox.showinfo(
                    "Batch Decryption Complete",
                    f"All {total} files were successfully authenticated and decrypted!\n\n"
                    f"Original file extensions and contents have been restored."
                )
                self.status_var.set(f"Successfully decrypted {total} files.")
            else:
                fail_details = "\n".join(f"• {os.path.basename(r[0])}: {r[3]}" for r in failed[:5])
                if len(failed) > 5:
                    fail_details += f"\n...and {len(failed) - 5} more"
                messagebox.showwarning(
                    "Batch Decryption Finished with Errors",
                    f"Processed {total} files:\n- {len(succeeded)} succeeded\n- {len(failed)} failed\n\nErrors:\n{fail_details}"
                )
                self.status_var.set(f"Decryption completed with {len(failed)} error(s).")

    def _on_view_history_click(self):
        """Open the Activity History Viewer dialog."""
        history_win = tk.Toplevel(self.root)
        history_win.title("Activity Audit History (SQLite: local_audit.db)")
        history_win.geometry("720x400")
        history_win.minsize(500, 300)

        container = ttk.Frame(history_win, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        header_lbl = ttk.Label(
            container,
            text="Local Cryptographic Audit Trail",
            font=("Helvetica", 12, "bold")
        )
        header_lbl.pack(anchor=tk.W, pady=(0, 8))

        columns = ("id", "timestamp", "operation", "file", "status")
        tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")

        tree.heading("id", text="ID")
        tree.heading("timestamp", text="Timestamp (UTC)")
        tree.heading("operation", text="Operation")
        tree.heading("file", text="File Path")
        tree.heading("status", text="Outcome Status")

        tree.column("id", width=40, anchor=tk.CENTER)
        tree.column("timestamp", width=140, anchor=tk.W)
        tree.column("operation", width=90, anchor=tk.CENTER)
        tree.column("file", width=240, anchor=tk.W)
        tree.column("status", width=160, anchor=tk.W)

        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def load_records():
            for item in tree.get_children():
                tree.delete(item)
            records = self.service.logger.fetch_history(limit=100)
            for r in records:
                tree.insert(
                    "",
                    tk.END,
                    values=(
                        r["log_id"],
                        r["timestamp"],
                        r["operation"],
                        os.path.basename(r["file_path"]),
                        r["status_message"]
                    )
                )

        load_records()

        btn_bar = ttk.Frame(history_win, padding=(12, 6))
        btn_bar.pack(fill=tk.X, side=tk.BOTTOM)

        refresh_btn = ttk.Button(btn_bar, text="Refresh", command=load_records)
        refresh_btn.pack(side=tk.LEFT)

        close_btn = ttk.Button(btn_bar, text="Close", command=history_win.destroy)
        close_btn.pack(side=tk.RIGHT)
