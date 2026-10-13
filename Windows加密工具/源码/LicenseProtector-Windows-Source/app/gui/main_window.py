"""Human-centered desktop workflow for PHP + Hyperf license deliveries.

The GUI owns only interaction state. Target normalization, runtime validation,
signing and packaging remain in dedicated domain modules so CLI and GUI builds
always follow the same policy.

Developer: Stephen Hu <stephenhu031028@gmail.com>
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime
import hashlib
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import uuid

from app.license.signer import LicenseSigner
from app.license.targets import LicenseTargets, normalize_domains, normalize_ipv4s
from app.package.builder import BuildRequest, PackageBuilder
from app.protector.deployment_bundle import build_linux_deployment_bundle
from app.protector.lpbc import create_runtime_key, load_runtime_key
from app.protector.native_backend import build_native_delivery, normalize_native_paths
from app.protector.php_hardener import normalize_source_paths
from app.runtime.profile import PHP_HYPERF


class Tooltip:
    """Small hover label for compact icon-only target controls."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.window: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show, add=True)
        widget.bind("<Leave>", self._hide, add=True)

    def _show(self, _event=None) -> None:
        if self.window is not None:
            return
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.geometry(f"+{self.widget.winfo_rootx()}+{self.widget.winfo_rooty() + self.widget.winfo_height() + 4}")
        tk.Label(self.window, text=self.text, bg="#202124", fg="white", padx=7, pady=3, font=("Segoe UI", 8)).pack()

    def _hide(self, _event=None) -> None:
        if self.window is not None:
            self.window.destroy()
            self.window = None


class MainWindow:
    """Collect build inputs while keeping the primary delivery workflow focused."""

    COLORS = {
        "accent": "#295CE8",
        "accent_dark": "#2049B8",
        "accent_soft": "#EDF2FF",
        "page": "#F4F6FA",
        "surface": "#FFFFFF",
        "surface_alt": "#EEF1F6",
        "border": "#DCE2EC",
        "text": "#17243A",
        "muted": "#596A82",
        "success": "#137333",
        "success_soft": "#E6F4EA",
        "warning": "#B06000",
        "warning_soft": "#FEF7E0",
        "danger": "#C5221F",
        "chip": "#EDF2FF",
        "chip_text": "#2049B8",
        "log": "#111D31",
        "nav": "#111D31",
        "nav_active": "#223455",
        "nav_muted": "#9EADC4",
    }

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.values = {key: tk.StringVar() for key in ("project", "version", "private", "public", "output", "php", "runtime_key")}
        self.delivery_mode = tk.StringVar(value="Native Loader 加密包")
        self.php_version = tk.StringVar(value="8.1+")
        self.target_inputs = {"domains": tk.StringVar(), "ipv4s": tk.StringVar()}
        self.target_items: dict[str, list[str]] = {"domains": [], "ipv4s": []}
        # Each target group renders compact rows instead of a fixed-height
        # Listbox. Empty groups therefore stay small and readable.
        self.target_lists: dict[str, tk.Frame] = {}
        self.target_counts: dict[str, tk.StringVar] = {}
        self.target_entries: dict[str, ttk.Entry] = {}
        self.hardened_paths: list[Path] = []
        self.hardened_selections: list[Path] = []
        self.hardening_status = tk.StringVar(value="未选择文件")
        self.key_status = tk.StringVar()
        self.status = tk.StringVar(value="就绪")
        self._busy = False
        self._status_label: tk.Label | None = None
        self._progress: ttk.Progressbar | None = None
        self._compact_layout: bool | None = None
        self._step = 0
        self._pages: list[ttk.Frame] = []
        self._nav_buttons: list[tk.Button] = []
        self._widget_states: list[tuple[tk.Widget, str]] = []
        self._last_delivery: Path | None = None
        self._selection_project = ""
        self._configure_window()
        self._configure_style()
        self._set_defaults()
        self._build_layout()
        self._refresh_key_status()
        self.values["project"].trace_add("write", self._project_changed)
        for key in ("version", "output"):
            self.values[key].trace_add("write", lambda *_args: self._refresh_summary())
        self.php_version.trace_add("write", lambda *_args: self._refresh_summary())
        self._show_step(0)

    def _configure_window(self) -> None:
        self.root.title("LicenseProtector - Windows 加密工具")
        width = min(1120, self.root.winfo_screenwidth() - 80)
        height = min(820, self.root.winfo_screenheight() - 100)
        self._startup_size = (width, height)
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(min(880, width), min(620, height))
        self.root.configure(bg=self.COLORS["page"])
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._center_window)

    def _center_window(self) -> None:
        self.root.update_idletasks()
        width, height = self.root.winfo_width(), self.root.winfo_height()
        # The first idle callback can run before Tk maps the top-level window.
        # Its measured size is then 1x1; use the configured size instead.
        if width <= 1 or height <= 1:
            width, height = self._startup_size
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class Rect(ctypes.Structure):
                _fields_ = (("left", wintypes.LONG), ("top", wintypes.LONG), ("right", wintypes.LONG), ("bottom", wintypes.LONG))

            class MonitorInfo(ctypes.Structure):
                _fields_ = (("cbSize", wintypes.DWORD), ("rcMonitor", Rect), ("rcWork", Rect), ("dwFlags", wintypes.DWORD))

            user32 = ctypes.windll.user32
            user32.MonitorFromWindow.argtypes = (wintypes.HWND, wintypes.DWORD)
            user32.MonitorFromWindow.restype = wintypes.HANDLE
            user32.GetMonitorInfoW.argtypes = (wintypes.HANDLE, ctypes.POINTER(MonitorInfo))
            user32.GetMonitorInfoW.restype = wintypes.BOOL
            user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
            user32.GetAncestor.restype = wintypes.HWND
            user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(Rect))
            user32.SetWindowPos.argtypes = (wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT)
            hwnd = user32.GetAncestor(wintypes.HWND(self.root.winfo_id()), 2)
            monitor = user32.MonitorFromWindow(hwnd, 2)
            info = MonitorInfo()
            info.cbSize = ctypes.sizeof(info)
            frame = Rect()
            if monitor and user32.GetMonitorInfoW(monitor, ctypes.byref(info)) and user32.GetWindowRect(hwnd, ctypes.byref(frame)):
                work = info.rcWork
                x = work.left + max((work.right - work.left - (frame.right - frame.left)) // 2, 0)
                y = work.top + max((work.bottom - work.top - (frame.bottom - frame.top)) // 2, 0)
                # Native frame/work-area coordinates share the same DPI space;
                # avoid translating them back through Tk's geometry parser.
                if user32.SetWindowPos(hwnd, None, x, y, 0, 0, 0x0015):
                    return
            else:
                x = max((self.root.winfo_screenwidth() - width) // 2, 0)
                y = max((self.root.winfo_screenheight() - height) // 2, 0)
        else:
            x = max((self.root.winfo_screenwidth() - width) // 2, 0)
            y = max((self.root.winfo_screenheight() - height) // 2, 0)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        self.root.option_add("*Font", ("Microsoft YaHei UI", 9))
        style.configure("TFrame", background=self.COLORS["surface"])
        style.configure("Page.TFrame", background=self.COLORS["page"])
        style.configure("Card.TLabelframe", background=self.COLORS["surface"], bordercolor=self.COLORS["border"], relief="solid")
        style.configure("Card.TLabelframe.Label", background=self.COLORS["surface"], foreground=self.COLORS["text"], font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("Field.TLabel", background=self.COLORS["surface"], foreground=self.COLORS["text"], font=("Microsoft YaHei UI", 9))
        style.configure("Hint.TLabel", background=self.COLORS["surface"], foreground=self.COLORS["muted"], font=("Microsoft YaHei UI", 9))
        style.configure("Status.TLabel", background=self.COLORS["page"], foreground=self.COLORS["muted"], font=("Microsoft YaHei UI", 9))
        style.configure("TEntry", padding=8, fieldbackground="white", bordercolor=self.COLORS["border"], lightcolor=self.COLORS["border"], darkcolor=self.COLORS["border"])
        style.map("TEntry", bordercolor=[("focus", self.COLORS["accent"])])
        style.configure("TCombobox", padding=7, fieldbackground="white", bordercolor=self.COLORS["border"], arrowsize=14)
        style.map("TCombobox", fieldbackground=[("readonly", "white")], selectbackground=[("readonly", "white")], selectforeground=[("readonly", self.COLORS["text"])])
        style.configure("Action.TButton", font=("Microsoft YaHei UI", 9), padding=(12, 8), foreground=self.COLORS["text"], background=self.COLORS["surface_alt"], borderwidth=0)
        style.configure("Quiet.TButton", font=("Microsoft YaHei UI", 9), padding=(10, 7), foreground=self.COLORS["muted"], background=self.COLORS["surface"], borderwidth=0)
        style.map("Action.TButton", background=[("active", "#E1E7F1")])
        style.map("Quiet.TButton", background=[("active", self.COLORS["accent_soft"])])
        style.configure("Treeview", background="white", fieldbackground="white", foreground=self.COLORS["text"], rowheight=30, borderwidth=0, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", background=self.COLORS["surface_alt"], foreground=self.COLORS["muted"], padding=(8, 7), relief="flat", font=("Microsoft YaHei UI", 9))
        style.map("Treeview", background=[("selected", self.COLORS["accent_soft"])], foreground=[("selected", self.COLORS["accent_dark"])])
        style.configure("TProgressbar", troughcolor=self.COLORS["surface_alt"], background=self.COLORS["accent"], bordercolor=self.COLORS["surface_alt"], lightcolor=self.COLORS["accent"], darkcolor=self.COLORS["accent"])

    @staticmethod
    def _application_dir() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parents[2]

    def _set_defaults(self) -> None:
        key_dir = self._key_dir()
        legacy_key_dir = self._application_dir() / "keys"
        if not (key_dir / "vendor_private.pem").exists() and not (key_dir / "vendor_public.pem").exists():
            if (legacy_key_dir / "vendor_private.pem").is_file() and (legacy_key_dir / "vendor_public.pem").is_file():
                key_dir.mkdir(parents=True, exist_ok=True)
                import shutil

                shutil.copy2(legacy_key_dir / "vendor_private.pem", key_dir / "vendor_private.pem")
                shutil.copy2(legacy_key_dir / "vendor_public.pem", key_dir / "vendor_public.pem")
        self.values["version"].set("1.1.0")
        self.values["private"].set(str(key_dir / "vendor_private.pem"))
        self.values["public"].set(str(key_dir / "vendor_public.pem"))
        self.values["output"].set(str(Path.home() / "Documents" / "LicenseProtector" / "deliveries"))
        self.values["php"].set("php")

    @staticmethod
    def _key_dir() -> Path:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "LicenseProtector" / "keys"

    def _runtime_key_path(self, project: Path) -> Path:
        identity = str(project.resolve()).casefold().encode("utf-8")
        project_id = hashlib.sha256(identity).hexdigest()[:24]
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "LicenseProtector" / "projects" / project_id / "runtime.key"

    def _build_layout(self) -> None:
        sidebar = tk.Frame(self.root, bg=self.COLORS["nav"], width=196)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        mark = tk.Canvas(sidebar, width=56, height=56, bg=self.COLORS["nav"], highlightthickness=0)
        mark.pack(anchor="w", padx=24, pady=(30, 12))
        mark.create_polygon(28, 3, 49, 13, 46, 37, 28, 52, 10, 37, 7, 13, fill=self.COLORS["accent"], outline="")
        mark.create_line(19, 26, 26, 33, 38, 19, fill="white", width=3)
        tk.Label(sidebar, text="LicenseProtector", bg=self.COLORS["nav"], fg="white", font=("Segoe UI", 13, "bold"), anchor="w").pack(fill="x", padx=24)
        tk.Label(sidebar, text="PHP 源码保护工作台", bg=self.COLORS["nav"], fg=self.COLORS["nav_muted"], font=("Microsoft YaHei UI", 9), anchor="w").pack(fill="x", padx=24, pady=(6, 30))
        for index, (title, hint) in enumerate((("选择项目", "指定源码与保护文件"), ("配置授权", "绑定域名与运行环境"), ("生成交付", "核对配置并安全打包"))):
            button = tk.Button(sidebar, text=f"0{index + 1}   {title}\n      {hint}", anchor="w", justify="left", command=lambda step=index: self._show_step(step), bg=self.COLORS["nav"], fg=self.COLORS["nav_muted"], activebackground=self.COLORS["nav_active"], activeforeground="white", relief="flat", borderwidth=0, padx=14, pady=14, font=("Microsoft YaHei UI", 10), cursor="hand2", takefocus=True)
            button.pack(fill="x", padx=12, pady=3)
            self._nav_buttons.append(button)
        bottom = tk.Frame(sidebar, bg=self.COLORS["nav"])
        bottom.pack(side="bottom", fill="x", padx=24, pady=24)
        tk.Frame(bottom, height=1, bg="#30405A").pack(fill="x", pady=(0, 16))
        tk.Label(bottom, text="WINDOWS → LINUX", bg=self.COLORS["nav"], fg=self.COLORS["nav_muted"], font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x")
        tk.Label(bottom, text="本机准备加密包\n服务器 Loader 执行", bg=self.COLORS["nav"], fg="#DCE5F2", font=("Microsoft YaHei UI", 9), justify="left", anchor="w").pack(fill="x", pady=(8, 0))

        workspace = ttk.Frame(self.root, style="Page.TFrame")
        workspace.pack(side="left", fill="both", expand=True)
        header = tk.Frame(workspace, bg=self.COLORS["page"], height=114)
        header.pack(fill="x", padx=28)
        header.pack_propagate(False)
        self._eyebrow = tk.Label(header, text="01 / PROJECT", bg=self.COLORS["page"], fg=self.COLORS["accent"], font=("Segoe UI", 9, "bold"), anchor="w")
        self._eyebrow.pack(fill="x", pady=(22, 5))
        self._page_title = tk.Label(header, bg=self.COLORS["page"], fg=self.COLORS["text"], font=("Microsoft YaHei UI", 22, "bold"), anchor="w")
        self._page_title.pack(fill="x")
        self._page_hint = tk.Label(header, bg=self.COLORS["page"], fg=self.COLORS["muted"], font=("Microsoft YaHei UI", 9), anchor="w")
        self._page_hint.pack(fill="x", pady=(5, 0))

        # Reserve the action bar before packing expanding content: primary
        # controls remain visible even on small displays and at high DPI.
        footer = ttk.Frame(workspace, style="Page.TFrame", padding=(28, 0, 28, 12))
        footer.pack(side="bottom", fill="x")
        self._status_label = tk.Label(footer, textvariable=self.status, bg=self.COLORS["page"], fg=self.COLORS["muted"], font=("Microsoft YaHei UI", 9), anchor="w")
        self._status_label.pack(side="left")
        footer.bind("<Configure>", lambda event: self._status_label.configure(wraplength=max(220, event.width - 320)), add=True)
        self._progress = ttk.Progressbar(footer, mode="indeterminate", length=110)
        ttk.Label(footer, text="LicenseProtector  /  Stephen Hu", style="Status.TLabel").pack(side="right")
        actions = ttk.Frame(workspace, style="Page.TFrame", padding=(28, 14, 28, 12))
        actions.pack(side="bottom", fill="x")
        self.back_button = ttk.Button(actions, text="← 上一步", style="Quiet.TButton", command=lambda: self._show_step(self._step - 1))
        self.back_button.pack(side="left")
        self.open_output_button = ttk.Button(actions, text="打开交付目录", style="Quiet.TButton", command=self._open_delivery)
        self.build_button = tk.Button(actions, text="下一步 →", command=self._primary_action, bg=self.COLORS["accent"], fg="white", activebackground=self.COLORS["accent_dark"], activeforeground="white", disabledforeground="#CDD7EB", relief="flat", borderwidth=0, padx=24, pady=10, font=("Microsoft YaHei UI", 10, "bold"), cursor="hand2", takefocus=True)
        self.build_button.pack(side="right")
        self.build_button.bind("<Enter>", lambda _event: self._set_build_hover(True), add=True)
        self.build_button.bind("<Leave>", lambda _event: self._set_build_hover(False), add=True)

        scroll_shell = ttk.Frame(workspace, style="Page.TFrame")
        scroll_shell.pack(fill="both", expand=True)
        self.scroll_canvas = tk.Canvas(scroll_shell, bg=self.COLORS["page"], highlightthickness=0, borderwidth=0)
        scroll_bar = ttk.Scrollbar(scroll_shell, orient="vertical", command=self.scroll_canvas.yview)
        self.scroll_canvas.configure(yscrollcommand=scroll_bar.set)
        self.scroll_canvas.pack(side="left", fill="both", expand=True)
        scroll_bar.pack(side="right", fill="y")
        page = ttk.Frame(self.scroll_canvas, style="Page.TFrame", padding=(28, 12, 28, 12))
        self._scroll_window = self.scroll_canvas.create_window((0, 0), window=page, anchor="nw")
        page.bind("<Configure>", self._sync_scroll_region)
        self.scroll_canvas.bind("<Configure>", self._resize_scroll_content)
        self.root.bind_all("<MouseWheel>", self._scroll_with_mouse, add=True)
        self.root.bind_all("<Button-4>", lambda _event: self.scroll_canvas.yview_scroll(-3, "units"), add=True)
        self.root.bind_all("<Button-5>", lambda _event: self.scroll_canvas.yview_scroll(3, "units"), add=True)

        for _ in range(3):
            self._pages.append(ttk.Frame(page, style="Page.TFrame"))
        self.project_card = self._project_card(self._pages[0])
        self.project_card.pack(fill="x")
        files = self._card(self._pages[0], "保护文件预览", "以下列表是实际处理范围；项目中的其他源文件保持原样。")
        files.pack(fill="x", pady=(16, 0))
        self.file_tree = ttk.Treeview(files, columns=("path",), show="headings", height=5, selectmode="extended")
        self.file_tree.heading("path", text="项目内相对路径")
        self.file_tree.column("path", width=440, stretch=True)
        self.file_tree.grid(row=1, column=0, columnspan=2, sticky="ew")
        file_scroll = ttk.Scrollbar(files, orient="vertical", command=self.file_tree.yview)
        file_scroll.grid(row=1, column=2, sticky="ns")
        self.file_tree.configure(yscrollcommand=file_scroll.set)
        self.file_empty = ttk.Label(files, text="尚未选择文件。点击“选文件”或“选目录”开始。", style="Hint.TLabel")
        self.file_empty.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(files, text="移除选中", style="Quiet.TButton", command=self._remove_selected_files).grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.file_tree.bind("<Delete>", lambda _event: self._remove_selected_files())

        config = ttk.Frame(self._pages[1], style="Page.TFrame")
        config.pack(fill="x")
        config.columnconfigure(0, weight=3)
        config.columnconfigure(1, weight=2)
        self.config = config
        self.runtime_card = self._runtime_card(config)
        self.license_card = self._license_card(config)
        self._key_card(self._pages[1]).pack(fill="x", pady=(16, 0))
        self._delivery_card(self._pages[2]).pack(fill="x")
        log_frame = self._card(self._pages[2], "生成记录", "生成进度和结果会保留在这里。")
        log_frame.pack(fill="x", pady=(12, 0))
        log_body = tk.Frame(log_frame, bg=self.COLORS["log"])
        log_body.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.log = tk.Text(log_body, height=6, state="disabled", wrap="word", bg=self.COLORS["log"], fg="#DCE5F2", insertbackground="white", relief="flat", padx=14, pady=12, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(log_body, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=scrollbar.set)
        self.log.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.root.bind("<Control-Return>", lambda _event: self.build(), add=True)

    def _show_step(self, step: int) -> None:
        if self._busy or not 0 <= step < len(self._pages):
            return
        if self._step == 1 and step == 2 and not self._commit_target_inputs():
            return
        if self._step == 1 and step == 2:
            try:
                LicenseTargets.create(self.target_items["domains"], self.target_items["ipv4s"])
            except ValueError:
                self._feedback("请添加至少一个授权域名或服务器 IPv4", "warning")
                self.target_entries["domains"].focus_set()
                return
        self._step = step
        for index, page in enumerate(self._pages):
            page.pack_forget()
            self._nav_buttons[index].configure(bg=self.COLORS["nav_active"] if index == step else self.COLORS["nav"], fg="white" if index == step else self.COLORS["nav_muted"])
        self._pages[step].pack(fill="x")
        titles = ("选择要保护的项目", "让授权与环境匹配", "准备好，开始交付")
        hints = ("选择项目，再确认本次要处理的 PHP 文件。", "添加允许访问的域名或服务器 IPv4，选择最低 PHP 版本。", "核对本次配置，生成可交付的文件和安装包。")
        self._eyebrow.configure(text=("01 / PROJECT", "02 / LICENSE", "03 / DELIVERY")[step])
        self._page_title.configure(text=titles[step])
        self._page_hint.configure(text=hints[step])
        if hasattr(self, "delivery_hint"):
            self.delivery_hint.configure(text="将生成 PHP 加密目录和项目专属 Linux 安装 ZIP。" if self.delivery_mode.get() == "Native Loader 加密包" else "将生成包含授权文件和选中文件处理结果的标准授权 ZIP。")
        self.back_button.configure(state="disabled" if step == 0 else "normal")
        self.build_button.configure(text="生成交付包  →" if step == 2 else "下一步  →")
        self._refresh_summary()
        self.root.update_idletasks()
        self._sync_scroll_region()
        self.scroll_canvas.yview_moveto(0)

    def _primary_action(self) -> None:
        if self._busy:
            return
        if self._step == 2:
            self.build()
            return
        if self._step == 0:
            project = Path(self.values["project"].get()).expanduser()
            if not self.values["project"].get().strip() or not project.is_dir():
                self._feedback("请先选择有效的项目目录", "warning")
                self.project_entry.focus_set()
                return
            try:
                paths = self._normalized_protected_paths(project)
                if self.delivery_mode.get() == "Native Loader 加密包" and not paths:
                    raise ValueError("请选择至少一个要加密的 PHP 文件")
            except (OSError, ValueError) as exc:
                self._feedback(str(exc), "warning")
                return
        self._show_step(self._step + 1)

    def _feedback(self, message: str, tone: str = "muted") -> None:
        self.status.set(message)
        if self._status_label is not None:
            self._status_label.configure(fg=self.COLORS[tone])

    def _delivery_card(self, parent: ttk.Frame) -> ttk.LabelFrame:
        card = self._card(parent, "本次交付", "密钥自动准备并复用；生成前请确认路径和授权目标。")
        self.summary_values: dict[str, tk.StringVar] = {}
        for row, (key, label) in enumerate((("project", "项目"), ("mode", "保护方式"), ("files", "处理范围"), ("targets", "授权目标"), ("runtime", "运行环境")), start=1):
            ttk.Label(card, text=label, style="Field.TLabel", width=12).grid(row=row, column=0, sticky="nw", pady=7)
            value = tk.StringVar()
            self.summary_values[key] = value
            ttk.Label(card, textvariable=value, style="Hint.TLabel", wraplength=530).grid(row=row, column=1, columnspan=2, sticky="w", pady=7)
        self._field(card, 5, "输出目录", "output", "output")
        self.delivery_hint = ttk.Label(card, style="Hint.TLabel", wraplength=520)
        self.delivery_hint.grid(row=7, column=1, columnspan=2, sticky="w", pady=(8, 0))
        return card

    def _refresh_summary(self) -> None:
        if not hasattr(self, "summary_values"):
            return
        self.summary_values["project"].set(self.values["project"].get() or "尚未选择项目")
        self.summary_values["mode"].set(self.delivery_mode.get())
        self.summary_values["files"].set(f"{len(self.hardened_paths)} 个 PHP 文件")
        targets = [*self.target_items["domains"], *self.target_items["ipv4s"]]
        self.summary_values["targets"].set("、".join(targets) or "尚未添加域名或 IPv4")
        self.summary_values["runtime"].set(f"PHP {self.php_version.get()} · Hyperf · 产品 {self.values['version'].get()}")

    def _open_delivery(self) -> None:
        if self._last_delivery is None or not self._last_delivery.exists():
            self._feedback("交付目录已移动或不存在", "warning")
            return
        try:
            os.startfile(str(self._last_delivery))
        except OSError as exc:
            self._feedback(f"无法打开交付目录：{exc}", "danger")

    def _set_build_hover(self, active: bool) -> None:
        if self._busy:
            return
        self.build_button.configure(bg=self.COLORS["accent_dark"] if active else self.COLORS["accent"])

    def _set_busy(self, busy: bool, message: str) -> None:
        if busy == self._busy:
            return
        self._busy = busy
        if busy:
            self._widget_states.clear()
            pending: list[tk.Widget] = [self.root]
            while pending:
                widget = pending.pop()
                pending.extend(widget.winfo_children())
                if isinstance(widget, (tk.Button, ttk.Button, ttk.Entry, ttk.Combobox)):
                    self._widget_states.append((widget, str(widget.cget("state"))))
                    widget.configure(state="disabled")
            self.build_button.configure(text="正在生成…", bg=self.COLORS["accent_dark"])
        else:
            for widget, state in self._widget_states:
                if widget.winfo_exists():
                    widget.configure(state=state)
            self._widget_states.clear()
            self.build_button.configure(text="生成交付包  →", bg=self.COLORS["accent"])
        self._feedback(message, "accent" if busy else "muted")
        if self._progress is not None:
            if busy:
                self._progress.pack(side="left", padx=(12, 0))
                self._progress.start(12)
            else:
                self._progress.stop()
                self._progress.pack_forget()
        if self._status_label is not None:
            self._status_label.configure(fg=self.COLORS["accent"] if busy else self.COLORS["muted"])

    def _close(self) -> None:
        if self._busy:
            messagebox.showwarning("正在生成", "交付包仍在生成中，请等待当前任务完成。")
            return
        self.root.destroy()

    def _sync_scroll_region(self, _event=None) -> None:
        """Make the canvas height follow dynamic authorization target rows."""
        self.scroll_canvas.configure(scrollregion=self.scroll_canvas.bbox("all"))

    def _resize_scroll_content(self, event) -> None:
        """Stretch content horizontally and switch card layout at narrow widths."""
        self.scroll_canvas.itemconfigure(self._scroll_window, width=event.width)
        self._apply_responsive_layout(event.width < 850)

    def _apply_responsive_layout(self, compact: bool) -> None:
        """Use two columns on desktop and one readable column on narrow windows."""
        if compact == self._compact_layout:
            return
        self._compact_layout = compact
        if compact:
            self.license_card.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=(0, 16))
            self.runtime_card.grid(row=1, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        else:
            self.license_card.grid(row=0, column=0, columnspan=1, sticky="new", padx=(0, 8), pady=0)
            self.runtime_card.grid(row=0, column=1, columnspan=1, sticky="new", padx=(8, 0), pady=0)

    def _scroll_with_mouse(self, event) -> str | None:
        """Scroll configuration without stealing the dedicated log widget wheel."""
        if event.widget in (self.log, self.file_tree) or isinstance(event.widget, ttk.Combobox):
            return None
        if event.delta:
            self.scroll_canvas.yview_scroll(-int(event.delta / 120), "units")
            return "break"
        return None

    def _card(self, parent: ttk.Frame, title: str, hint: str) -> ttk.LabelFrame:
        card = ttk.LabelFrame(parent, text=title, style="Card.TLabelframe", padding=(20, 14, 20, 18))
        hint_label = ttk.Label(card, text=hint, style="Hint.TLabel", wraplength=450)
        hint_label.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 12))
        def wrap_card(event) -> None:
            hint_label.configure(wraplength=max(180, event.width - 44))
            for child in card.winfo_children():
                if child is hint_label or not isinstance(child, ttk.Label):
                    continue
                if child.cget("wraplength") and float(child.cget("wraplength")):
                    child.configure(wraplength=max(180, event.width - (180 if int(child.grid_info().get("column", 0)) else 44)))

        card.bind("<Configure>", wrap_card, add=True)
        card.columnconfigure(1, weight=1)
        return card

    def _field(self, parent: ttk.LabelFrame, row: int, label: str, key: str, browse: str | None = None) -> None:
        field_row = row + 1
        ttk.Label(parent, text=label, style="Field.TLabel", width=12).grid(row=field_row, column=0, sticky="w", pady=4)
        entry = ttk.Entry(parent, textvariable=self.values[key])
        entry.grid(row=field_row, column=1, sticky="ew", pady=4, padx=(0, 8))
        if key == "project":
            self.project_entry = entry
        if browse:
            ttk.Button(parent, text="浏览...", style="Action.TButton", command=lambda: self._browse(key, browse)).grid(row=field_row, column=2, sticky="e", pady=2)

    def _project_card(self, parent: ttk.Frame) -> ttk.LabelFrame:
        card = self._card(parent, "项目与保护方式", "选择本机 Hyperf 源码。输出目录可在最后一步设置。")
        self._field(card, 0, "项目目录", "project", "project")
        ttk.Label(card, text="保护方式", style="Field.TLabel", width=12).grid(row=2, column=0, sticky="w", pady=4)
        mode = ttk.Combobox(card, textvariable=self.delivery_mode, values=("标准授权包", "Native Loader 加密包"), state="readonly")
        mode.grid(row=2, column=1, columnspan=2, sticky="ew", pady=4)
        mode.bind("<<ComboboxSelected>>", lambda _event: self._refresh_native_fields())
        self.protected_paths_label = ttk.Label(card, text="加固文件", style="Field.TLabel", width=12)
        self.protected_paths_label.grid(row=3, column=0, sticky="w", pady=(10, 4))
        hardening_actions = ttk.Frame(card)
        hardening_actions.grid(row=3, column=1, columnspan=2, sticky="ew", pady=(10, 4))
        ttk.Label(hardening_actions, textvariable=self.hardening_status, style="Hint.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Button(hardening_actions, text="选文件...", style="Action.TButton", command=self._select_hardened_files).pack(side="right")
        ttk.Button(hardening_actions, text="选目录...", style="Action.TButton", command=self._select_hardened_directory).pack(side="right", padx=(0, 5))
        ttk.Button(hardening_actions, text="清除", style="Action.TButton", command=self._clear_hardened_paths).pack(side="right", padx=(0, 5))
        self.protected_paths_hint = ttk.Label(
            card,
            text="免费模式仅移除普通注释与冗余空白；勾选项会纳入签名清单。",
            style="Hint.TLabel",
            wraplength=520,
        )
        self.protected_paths_hint.grid(row=4, column=1, columnspan=2, sticky="w", pady=(0, 4))
        self.local_php_label = ttk.Label(card, text="本机 PHP", style="Field.TLabel", width=12)
        self.local_php_label.grid(row=5, column=0, sticky="w", pady=4)
        self.local_php_entry = ttk.Entry(card, textvariable=self.values["php"])
        self.local_php_entry.grid(row=5, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(card, text="运行密钥", style="Field.TLabel", width=12).grid(row=6, column=0, sticky="w", pady=4)
        self.runtime_key_status = tk.StringVar(value="按项目自动生成并复用")
        ttk.Label(card, textvariable=self.runtime_key_status, style="Hint.TLabel").grid(row=6, column=1, sticky="w", pady=4)
        self.runtime_key_generate = ttk.Button(card, text="准备密钥", style="Action.TButton", command=self._generate_runtime_key)
        self.runtime_key_generate.grid(row=6, column=2, sticky="e", pady=2)
        ttk.Button(card, text="扫描项目", style="Quiet.TButton", command=self.scan).grid(row=7, column=1, sticky="w", pady=(8, 0))
        self._refresh_native_fields()
        return card

    def _refresh_native_fields(self) -> None:
        enabled = self.delivery_mode.get() == "Native Loader 加密包"
        state = "normal" if enabled else "disabled"
        self.runtime_key_generate.configure(state=state)
        if enabled:
            self.local_php_label.grid_remove()
            self.local_php_entry.grid_remove()
            self.protected_paths_label.configure(text="加密保护文件")
            self.protected_paths_hint.configure(text="仅选中的 PHP 文件会加密；目录选择会跳过 vendor 等依赖目录。")
        else:
            self.local_php_label.grid()
            self.local_php_entry.grid()
            self.protected_paths_label.configure(text="加固文件")
            self.protected_paths_hint.configure(text="免费模式仅移除普通注释与冗余空白；勾选项会纳入签名清单。")
        self.runtime_key_status.set("按项目自动生成并复用" if enabled else "此模式无需运行密钥")
        self._refresh_protected_selection_count()
        self._refresh_summary()

    def _normalized_protected_paths(self, project: Path) -> tuple[Path, ...]:
        normalizer = normalize_native_paths if self.delivery_mode.get() == "Native Loader 加密包" else normalize_source_paths
        return normalizer(project, self.hardened_selections)

    def _refresh_protected_selection_count(self) -> None:
        project = Path(self.values["project"].get())
        if not self.hardened_selections or not project.is_dir():
            self.hardened_paths.clear()
            self.hardening_status.set("未选择文件")
            self._refresh_file_preview()
            return
        try:
            paths = self._normalized_protected_paths(project)
        except (OSError, ValueError):
            self.hardened_paths.clear()
            self.hardening_status.set("选择无效，请重新选择")
            self._refresh_file_preview()
            return
        self.hardened_paths = list(paths)
        self.hardening_status.set(f"已选择 {len(paths)} 个 PHP 文件")
        self._refresh_file_preview()

    def _project_changed(self, *_args) -> None:
        try:
            identity = str(Path(self.values["project"].get()).expanduser().resolve()).casefold()
        except (OSError, ValueError):
            identity = self.values["project"].get().casefold()
        if identity != self._selection_project:
            self.hardened_selections.clear()
            self.hardened_paths.clear()
            self.values["runtime_key"].set("")
            self._selection_project = identity
            self.runtime_key_status.set("按项目自动生成并复用" if self.delivery_mode.get() == "Native Loader 加密包" else "此模式无需运行密钥")
            self._last_delivery = None
            self.open_output_button.pack_forget()
            self._refresh_protected_selection_count()
        self._refresh_summary()

    def _refresh_file_preview(self) -> None:
        if not hasattr(self, "file_tree"):
            return
        items = self.file_tree.get_children()
        if items:
            self.file_tree.delete(*items)
        for index, path in enumerate(self.hardened_paths):
            self.file_tree.insert("", "end", iid=str(index), values=(path.as_posix(),))
        self.file_empty.configure(text="可多选文件后点击“移除选中”，或按 Delete。" if self.hardened_paths else "尚未选择文件。点击“选文件”或“选目录”开始。")
        self._refresh_summary()

    def _remove_selected_files(self) -> None:
        if self._busy:
            return
        indexes = {int(item) for item in self.file_tree.selection()}
        if not indexes:
            self._feedback("请先在列表中选择要移除的文件", "warning")
            return
        self.hardened_paths = [path for index, path in enumerate(self.hardened_paths) if index not in indexes]
        self.hardened_selections = list(self.hardened_paths)
        self._refresh_protected_selection_count()

    def _generate_runtime_key(self) -> None:
        project = Path(self.values["project"].get()).expanduser()
        if not self.values["project"].get().strip() or not project.is_dir():
            messagebox.showwarning("需要选择项目", "请先选择 PHP 项目目录，再准备项目运行密钥。")
            return
        key_path = self._runtime_key_path(project)
        try:
            if not key_path.exists():
                create_runtime_key(key_path)
            load_runtime_key(key_path)
        except OSError as exc:
            messagebox.showerror("生成失败", f"无法保存运行密钥：{exc}")
            return
        except ValueError as exc:
            messagebox.showerror("密钥不可用", f"现有项目运行密钥无效，未覆盖该文件：{exc}")
            return
        self.values["runtime_key"].set(str(key_path))
        self.runtime_key_status.set("已准备，可由同一项目继续复用")
        self.write_log(f"项目运行密钥已准备：{key_path.parent}")
        self.status.set("项目运行密钥已准备")

    def _add_hardened_paths(self, selections: list[Path]) -> None:
        project = Path(self.values["project"].get())
        if not self.values["project"].get().strip() or not project.is_dir():
            messagebox.showwarning("需要选择项目", "请先选择有效的 Hyperf 项目目录。")
            return
        try:
            normalizer = normalize_native_paths if self.delivery_mode.get() == "Native Loader 加密包" else normalize_source_paths
            paths = normalizer(project, [*self.hardened_selections, *selections])
        except ValueError as exc:
            messagebox.showwarning("加固文件无效", str(exc))
            return
        self.hardened_selections = list(paths)
        self.hardened_paths = list(paths)
        self.hardening_status.set(f"已选择 {len(paths)} 个 PHP 文件")
        self._refresh_file_preview()
        self._feedback(f"已确认 {len(paths)} 个 PHP 文件", "success")


    def _select_hardened_files(self) -> None:
        project = Path(self.values["project"].get())
        if not self.values["project"].get().strip() or not project.is_dir():
            self._feedback("请先选择项目目录，再选择保护文件", "warning")
            return
        selected = filedialog.askopenfilenames(
            title="选择需要加固的 PHP 文件",
            initialdir=str(project) if project.is_dir() else None,
            filetypes=[("PHP 文件", "*.php")],
        )
        if selected:
            self._add_hardened_paths([Path(path) for path in selected])

    def _select_hardened_directory(self) -> None:
        project = Path(self.values["project"].get())
        if not self.values["project"].get().strip() or not project.is_dir():
            self._feedback("请先选择项目目录，再选择保护目录", "warning")
            return
        selected = filedialog.askdirectory(
            title="选择需要加固的目录",
            initialdir=str(project) if project.is_dir() else None,
        )
        if selected:
            self._add_hardened_paths([Path(selected)])

    def _clear_hardened_paths(self) -> None:
        if self._busy:
            return
        self.hardened_paths.clear()
        self.hardened_selections.clear()
        self.hardening_status.set("未选择文件")
        self._refresh_file_preview()

    def _runtime_card(self, parent: ttk.Frame) -> ttk.LabelFrame:
        card = self._card(parent, "运行环境", "签名记录目标服务器运行环境。")
        ttk.Label(card, text="语言", style="Field.TLabel", width=12).grid(row=1, column=0, sticky="w", pady=4)
        language = ttk.Label(card, text=PHP_HYPERF.language, style="Hint.TLabel")
        language.grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Label(card, text="框架", style="Field.TLabel", width=12).grid(row=2, column=0, sticky="w", pady=4)
        framework = ttk.Label(card, text=PHP_HYPERF.framework, style="Hint.TLabel")
        framework.grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Label(card, text="最低 PHP", style="Field.TLabel", width=12).grid(row=3, column=0, sticky="w", pady=4)
        versions = tuple(f"{version}+" for version in PHP_HYPERF.minimum_versions)
        ttk.Combobox(card, textvariable=self.php_version, values=versions, state="readonly").grid(row=3, column=1, sticky="ew", pady=4)
        ttk.Label(card, text="产品版本", style="Field.TLabel", width=12).grid(row=4, column=0, sticky="w", pady=(8, 4))
        ttk.Entry(card, textvariable=self.values["version"]).grid(row=4, column=1, columnspan=2, sticky="ew", pady=(8, 4))
        return card

    def _license_card(self, parent: ttk.Frame) -> ttk.LabelFrame:
        card = self._card(parent, "授权目标", "任意一个域名或服务器 IPv4 匹配即可通过。")
        self._target_editor(card, 1, "授权域名", "domains", "例如 api.example.com")
        self._target_editor(card, 5, "服务器 IPv4", "ipv4s", "例如 10.0.3.6")
        return card

    def _target_editor(self, parent: ttk.LabelFrame, row: int, title: str, key: str, placeholder: str) -> None:
        heading = tk.Frame(parent, bg=self.COLORS["surface"])
        heading.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(2, 4))
        heading.columnconfigure(1, weight=1)
        tk.Label(heading, text=title, bg=self.COLORS["surface"], fg=self.COLORS["text"], font=("Microsoft YaHei UI", 9, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        count = tk.StringVar(value="0 个")
        self.target_counts[key] = count
        tk.Label(heading, textvariable=count, bg=self.COLORS["surface"], fg=self.COLORS["muted"], font=("Segoe UI", 8), anchor="e").grid(row=0, column=1, sticky="e")
        entry = ttk.Entry(parent, textvariable=self.target_inputs[key])
        self.target_entries[key] = entry
        entry.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(0, 2), padx=(0, 6))
        entry.bind("<Return>", lambda _event, kind=key: self._add_target(kind))
        add = tk.Button(parent, text="添加", command=lambda kind=key: self._add_target(kind), bg=self.COLORS["accent_soft"], fg=self.COLORS["accent_dark"], activebackground="#DCE6FF", activeforeground=self.COLORS["accent_dark"], relief="flat", padx=10, pady=7, cursor="hand2", font=("Microsoft YaHei UI", 9), takefocus=True)
        add.grid(row=row + 1, column=2, sticky="e", pady=(0, 2))
        Tooltip(add, f"添加{title}")
        ttk.Label(parent, text=placeholder, style="Hint.TLabel").grid(row=row + 2, column=0, columnspan=3, sticky="w", pady=(0, 3))
        rows = tk.Frame(parent, bg=self.COLORS["surface"])
        rows.grid(row=row + 3, column=0, columnspan=3, sticky="ew", pady=(0, 3))
        self.target_lists[key] = rows
        self._refresh_target_list(key)

    def _add_target(self, kind: str) -> bool:
        if self._busy:
            return False
        raw = self.target_inputs[kind].get().strip()
        if not raw:
            return True
        try:
            values = normalize_domains(raw) if kind == "domains" else normalize_ipv4s(raw)
        except ValueError:
            label = "域名" if kind == "domains" else "IPv4"
            self._feedback(f"{label}格式无效，请检查输入", "warning")
            self.target_entries[kind].focus_set()
            return False
        self.target_items[kind].extend(item for item in values if item not in self.target_items[kind])
        self.target_inputs[kind].set("")
        self._refresh_target_list(kind)
        self._feedback("授权目标已添加", "success")
        return True

    def _commit_target_inputs(self) -> bool:
        return self._add_target("domains") and self._add_target("ipv4s")

    def _remove_target(self, kind: str, index: int) -> None:
        """Remove one visible target row; the row owns its own action."""
        if not self._busy and 0 <= index < len(self.target_items[kind]):
            del self.target_items[kind][index]
            self._refresh_target_list(kind)

    def _refresh_target_list(self, kind: str) -> None:
        rows = self.target_lists[kind]
        for child in rows.winfo_children():
            child.destroy()
        items = self.target_items[kind]
        self.target_counts[kind].set(f"{len(items)} 个")
        self._refresh_summary()
        if not items:
            tk.Label(rows, text="尚未添加", bg=self.COLORS["surface"], fg=self.COLORS["muted"], font=("Microsoft YaHei UI", 9), anchor="w").pack(fill="x", pady=(1, 5))
            return
        for index, item in enumerate(items):
            item_row = tk.Frame(rows, bg=self.COLORS["chip"], highlightbackground="#D2E3FC", highlightthickness=1)
            item_row.pack(fill="x", pady=(0, 3))
            tk.Label(item_row, text=item, bg=self.COLORS["chip"], fg=self.COLORS["chip_text"], font=("Microsoft YaHei UI", 9), anchor="w", padx=9, pady=6, wraplength=320).pack(side="left", fill="x", expand=True)
            remove = tk.Button(item_row, text="×", command=lambda target=kind, target_index=index: self._remove_target(target, target_index), bg=self.COLORS["chip"], fg=self.COLORS["muted"], activebackground="#FCE8E6", activeforeground="#C5221F", relief="flat", borderwidth=0, width=3, cursor="hand2", font=("Segoe UI", 10))
            remove.pack(side="right", padx=(0, 3))
            Tooltip(remove, "移除该授权目标")

    def _key_card(self, parent: ttk.Frame) -> ttk.LabelFrame:
        card = self._card(parent, "厂商身份", "私钥只留在这台 Windows 电脑；Linux 安装包只自动带公钥。")
        ttk.Label(card, textvariable=self.key_status, style="Hint.TLabel").grid(row=1, column=0, columnspan=3, sticky="w")
        ttk.Label(card, text="生成时自动初始化并复用。请备份密钥目录，以便为已有项目续签。", style="Hint.TLabel", wraplength=500).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        buttons = ttk.Frame(card)
        buttons.grid(row=3, column=0, columnspan=3, sticky="w", pady=(12, 0))
        ttk.Button(buttons, text="检查 / 初始化身份", style="Quiet.TButton", command=self.generate_keys).pack(side="left")
        ttk.Button(buttons, text="打开密钥目录", style="Quiet.TButton", command=self.open_key_directory).pack(side="left", padx=(8, 0))
        return card

    def _browse(self, key: str, kind: str) -> None:
        if kind in ("project", "output"):
            selected = filedialog.askdirectory(title="选择项目目录" if kind == "project" else "选择输出目录")
        else:
            selected = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("PEM 密钥", "*.pem"), ("所有文件", "*.*")])
        if selected:
            if key == "project" and Path(selected).resolve() != Path(self.values[key].get()).resolve():
                self.hardened_paths.clear()
                self.hardened_selections.clear()
                self.hardening_status.set("未选择文件")
            self.values[key].set(selected)
            if key in ("private", "public"):
                self._refresh_key_status()

    def _refresh_key_status(self) -> None:
        private, public = Path(self.values["private"].get()), Path(self.values["public"].get())
        if private.is_file() and public.is_file():
            try:
                if not LicenseSigner.keys_match(LicenseSigner.load_private(private), LicenseSigner.load_public(public)):
                    raise ValueError("key pair mismatch")
                self.key_status.set("厂商身份已初始化")
            except (OSError, ValueError, TypeError):
                self.key_status.set("密钥对异常，请勿用于签发")
        elif private.exists() or public.exists():
            self.key_status.set("检测到不完整密钥，请先恢复原有备份")
        else:
            self.key_status.set("首次使用，请初始化厂商身份")

    def generate_keys(self) -> None:
        private, public = Path(self.values["private"].get()), Path(self.values["public"].get())
        try:
            if private.exists() or public.exists():
                if not (private.is_file() and public.is_file()):
                    raise ValueError("只发现了密钥对的一部分。为避免破坏已有授权，未生成或覆盖密钥；请从备份恢复另一份文件。")
                if not LicenseSigner.keys_match(LicenseSigner.load_private(private), LicenseSigner.load_public(public)):
                    raise ValueError("现有公钥和私钥不匹配，未修改任何密钥文件。")
                self._refresh_key_status()
                messagebox.showinfo("厂商身份已就绪", "已沿用当前厂商密钥，不会覆盖。\n密钥目录：" + str(private.parent))
                return
            private.parent.mkdir(parents=True, exist_ok=True)
            public.parent.mkdir(parents=True, exist_ok=True)
            LicenseSigner.generate_keypair(private, public)
            self._refresh_key_status()
            self.write_log(f"厂商密钥已生成：{private.parent}")
            self.status.set("厂商身份已初始化")
            messagebox.showinfo("厂商身份已初始化", "公钥和私钥已自动生成并保存在 Windows 用户数据目录。\n请备份密钥目录；私钥不会进入服务器安装包。")
        except Exception as exc:
            messagebox.showerror("生成失败", str(exc))

    def _ensure_vendor_identity(self) -> None:
        private, public = Path(self.values["private"].get()), Path(self.values["public"].get())
        if private.exists() or public.exists():
            if not (private.is_file() and public.is_file()):
                raise ValueError("厂商密钥不完整；请从备份恢复密钥对后再生成交付包。")
            if not LicenseSigner.keys_match(LicenseSigner.load_private(private), LicenseSigner.load_public(public)):
                raise ValueError("厂商公钥和私钥不匹配；未修改密钥，请从备份恢复正确的密钥对。")
            return
        private.parent.mkdir(parents=True, exist_ok=True)
        LicenseSigner.generate_keypair(private, public)
        self._refresh_key_status()
        self.write_log(f"已自动初始化厂商身份：{private.parent}")

    def open_key_directory(self) -> None:
        directory = self._key_dir()
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(directory))
        except OSError as exc:
            messagebox.showerror("无法打开目录", str(exc))

    def write_log(self, message: str) -> None:
        self.root.after(0, self._append_log, message)

    def _append_log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{datetime.now():%H:%M:%S}  {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def scan(self) -> None:
        if self._busy:
            return
        project = Path(self.values["project"].get()).expanduser()
        if not self.values["project"].get().strip() or not project.is_dir():
            self._feedback("请先选择有效的 Hyperf 项目目录", "warning")
            return
        try:
            from app.scanner.project_scanner import ProjectScanner

            info = ProjectScanner().scan(project)
            PHP_HYPERF.validate_project_framework(info.framework)
            self.write_log(f"检测到 PHP · {info.framework}，入口：{info.entry}")
            self._feedback(f"项目已确认：{info.framework} · {info.entry}", "success")
        except Exception as exc:
            messagebox.showerror("扫描失败", str(exc))

    def build(self) -> None:
        if self._busy or not self._commit_target_inputs():
            return
        project = Path(self.values["project"].get()).expanduser()
        if not self.values["project"].get().strip() or not project.is_dir():
            self._show_step(0)
            self._feedback("请先选择有效的 Hyperf 项目目录", "warning")
            return
        try:
            targets = LicenseTargets.create(self.target_items["domains"], self.target_items["ipv4s"])
            if not self.values["output"].get().strip():
                raise ValueError("请填写交付输出目录")
            output = Path(self.values["output"].get()).expanduser().resolve()
            if output.is_relative_to(project.resolve()):
                raise ValueError("输出目录不能位于源码项目内，请选择独立目录")
            if not self.values["version"].get().strip():
                raise ValueError("请填写产品版本")
            self._refresh_protected_selection_count()
            selections = self._normalized_protected_paths(project)
            if self.delivery_mode.get() == "Native Loader 加密包" and not selections:
                raise ValueError("请选择至少一个需要加密保护的 PHP 文件")
            self._ensure_vendor_identity()
            self._show_step(2)
            self._last_delivery = None
            self.open_output_button.pack_forget()
            if self.delivery_mode.get() == "Native Loader 加密包":
                runtime_key = self._runtime_key_path(project)
                if not runtime_key.exists():
                    create_runtime_key(runtime_key)
                load_runtime_key(runtime_key)
                self.values["runtime_key"].set(str(runtime_key))
                self.runtime_key_status.set("已准备，可由同一项目继续复用")
                private_key = Path(self.values["private"].get())
                license_id = f"LIC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                product_version = self.values["version"].get().strip()
                php_min_version = self.php_version.get()
                self._set_busy(True, "正在生成 Native 加密交付包")
                self.write_log("开始生成 Native Loader 加密包，界面保持响应…")
                threading.Thread(
                    target=self._native_build_worker,
                    args=(project, selections, targets, runtime_key, output, private_key, Path(self.values["public"].get()), license_id, product_version, php_min_version),
                    daemon=True,
                ).start()
                return
            request = BuildRequest(
                project=project,
                domains=targets.domains,
                ipv4s=targets.ipv4s,
                php_min_version=self.php_version.get(),
                product_version=self.values["version"].get().strip(),
                output=output,
                private_key=Path(self.values["private"].get()),
                public_key=Path(self.values["public"].get()),
                hardened_paths=self._normalized_protected_paths(project),
                php_executable=self.values["php"].get().strip() or "php",
            )
        except (OSError, ValueError, TypeError) as exc:
            self._feedback("请检查授权与交付配置", "warning")
            messagebox.showwarning("授权配置无效", str(exc))
            return
        self._set_busy(True, "正在生成交付包")
        self.write_log("开始后台打包，界面保持响应…")
        threading.Thread(target=self._build_worker, args=(request,), daemon=True).start()

    def _native_build_worker(
        self,
        project: Path,
        selections: tuple[Path, ...],
        targets: LicenseTargets,
        runtime_key: Path,
        output: Path,
        private_key: Path,
        public_key: Path,
        license_id: str,
        product_version: str,
        php_min_version: str,
    ) -> None:
        try:
            delivery = build_native_delivery(
                project,
                selections,
                output,
                private_key,
                runtime_key,
                license_id,
                product_version,
                targets.domains,
                targets.ipv4s,
                php_min_version,
            )
            self.write_log(f"PHP 加密交付目录已生成：{delivery}")
            deployment_bundle = output.parent / f"{output.name}-{license_id}-Linux安装包.zip"
            build_linux_deployment_bundle(
                deployment_bundle,
                runtime_key,
                private_key,
                public_key,
            )
            self.write_log(f"Linux 项目安装包已生成：{deployment_bundle}")
            self.root.after(0, self._native_build_finished, delivery, deployment_bundle)
        except Exception as exc:
            self.root.after(0, self._build_failed, str(exc))

    def _native_build_finished(self, delivery: Path, deployment_bundle: Path) -> None:
        self._set_busy(False, "PHP 加密包和 Linux 安装包已生成")
        self._feedback("交付完成 · PHP 加密目录与 Linux 安装包已就绪", "success")
        self._last_delivery = delivery.parent
        self.open_output_button.pack(side="left", padx=(12, 0))
        self.write_log("交付完成。部署包包含运行密钥，请通过可信渠道传输。")
        messagebox.showinfo(
            "打包完成",
            "PHP 加密交付目录：\n"
            f"{delivery}\n\n"
            "Linux 项目安装包：\n"
            f"{deployment_bundle}\n\n"
            "Linux 安装包包含该项目的运行密钥，请仅通过可信渠道传输；厂商私钥不会包含在内。",
        )

    def _build_worker(self, request: BuildRequest) -> None:
        try:
            result = PackageBuilder(self.write_log).build(request)
            self.root.after(0, self._build_finished, result.zip_path)
        except Exception as exc:
            self.root.after(0, self._build_failed, str(exc))

    def _build_finished(self, zip_path: Path) -> None:
        self._set_busy(False, "交付包已生成")
        self._feedback("交付完成 · 授权包已就绪", "success")
        self._last_delivery = zip_path.parent
        self.open_output_button.pack(side="left", padx=(12, 0))
        messagebox.showinfo("打包完成", f"交付包已生成：\n{zip_path}")

    def _build_failed(self, error: str) -> None:
        self._set_busy(False, "打包失败")
        self._feedback("生成失败 · 请查看生成记录", "danger")
        self.write_log(f"生成失败：{error}")
        messagebox.showerror("打包失败", error)
