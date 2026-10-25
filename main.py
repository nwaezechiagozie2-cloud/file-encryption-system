#!/usr/bin/env python3
"""
Main Entry Point
================
Launches the File Encryption and Decryption Desktop Application.
"""

import sys
import tkinter as tk
from app.gui import AppGUI
from app.service import FileCryptoService
from app.db_logger import DBLogger


def main():
    """Start the Tkinter GUI application."""
    root = tk.Tk()
    
    # Initialize shared database logger and service
    db_logger = DBLogger()
    service = FileCryptoService(db_logger=db_logger)
    
    app = AppGUI(root=root, service=service)
    
    # Run the Tkinter main event loop
    root.mainloop()


if __name__ == "__main__":
    main()
