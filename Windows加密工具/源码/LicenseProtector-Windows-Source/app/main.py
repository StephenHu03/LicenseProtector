"""Tkinter entry point. Developer: Stephen Hu <stephenhu031028@gmail.com>."""
from __future__ import annotations

import sys
import tkinter as tk
from app.gui.main_window import MainWindow


def _enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        awareness = ctypes.c_void_p(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        ctypes.windll.user32.SetProcessDpiAwarenessContext(awareness)
    except (AttributeError, OSError):
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            pass


def main() -> int:
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    MainWindow(root)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
