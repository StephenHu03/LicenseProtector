"""Tkinter entry point. Developer: Stephen Hu <stephenhu031028@gmail.com>."""
from __future__ import annotations

import sys
import tkinter as tk
from app.gui.main_window import MainWindow


def main() -> int:
    root = tk.Tk()
    MainWindow(root)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
