"""Exercise the desktop workflow without using real vendor keys or dialogs."""

from pathlib import Path
import time
import tkinter as tk
import zipfile

import pytest

from app.gui.main_window import MainWindow


@pytest.fixture(scope="module")
def tk_host():
    host = tk.Tk()
    host.withdraw()
    yield host
    host.destroy()


@pytest.fixture
def desktop(tmp_path, monkeypatch, tk_host):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user-data"))
    monkeypatch.setattr(MainWindow, "_application_dir", staticmethod(lambda: tmp_path))
    root = tk.Toplevel(tk_host)
    root.withdraw()
    window = MainWindow(root)
    window.values["output"].set(str(tmp_path / "delivery"))
    try:
        yield root, window
    finally:
        root.update_idletasks()
        root.destroy()


def project_at(root: Path) -> Path:
    source = root / "app" / "Service"
    source.mkdir(parents=True)
    (source / "Core.php").write_text("<?php return 42;\n", encoding="utf-8")
    (source / "Other.php").write_text("<?php return 7;\n", encoding="utf-8")
    return root


def test_selections_are_cumulative_removable_and_reset_with_project(desktop, tmp_path):
    _, window = desktop
    project = project_at(tmp_path / "project")
    window.values["project"].set(str(project))
    window._add_hardened_paths([Path("app/Service/Core.php")])
    window._add_hardened_paths([Path("app/Service/Other.php")])
    assert len(window.file_tree.get_children()) == 2
    window.file_tree.selection_set("0")
    window._remove_selected_files()
    assert window.hardened_paths == [Path("app/Service/Other.php")]
    assert window._normalized_protected_paths(project) == (Path("app/Service/Other.php"),)
    window.values["project"].set(str(tmp_path / "another-project"))
    assert not window.hardened_paths
    assert not window.hardened_selections
    assert not window.file_tree.get_children()


def test_targets_are_validated_and_pending_input_is_committed(desktop):
    _, window = desktop
    window._show_step(1)
    window.target_inputs["ipv4s"].set("999.1.1.1")
    window._primary_action()
    assert window._step == 1
    assert window.target_inputs["ipv4s"].get() == "999.1.1.1"
    assert not window.target_items["ipv4s"]
    window.target_inputs["ipv4s"].set("")
    window.target_inputs["domains"].set("HTTPS://Api.Example.com:443,api.example.com")
    window._primary_action()
    assert window._step == 2
    assert window.target_items["domains"] == ["api.example.com"]
    assert window.summary_values["targets"].get() == "api.example.com"


def test_busy_state_blocks_reentry_and_restores_readonly_fields(desktop, monkeypatch):
    _, window = desktop
    window._show_step(2)
    window._set_busy(True, "正在生成")
    monkeypatch.setattr(window, "_ensure_vendor_identity", lambda: pytest.fail("build reentered"))
    window.build()
    window._show_step(0)
    assert window._step == 2
    assert str(window.project_entry.cget("state")) == "disabled"
    window._set_busy(False, "已完成")
    assert str(window.project_entry.cget("state")) == "normal"
    modes = [widget for widget, _ in window._widget_states]
    assert modes == []
    comboboxes = []
    pending = [window.root]
    while pending:
        widget = pending.pop()
        pending.extend(widget.winfo_children())
        if widget.winfo_class() == "TCombobox":
            comboboxes.append(widget)
    assert all(str(widget.cget("state")) == "readonly" for widget in comboboxes)


def test_native_gui_builds_delivery_and_current_linux_installer(desktop, tmp_path, monkeypatch):
    root, window = desktop
    project = project_at(tmp_path / "project")
    window.values["project"].set(str(project))
    window._add_hardened_paths([Path("app/Service/Core.php")])
    window.target_inputs["domains"].set("api.example.com")
    dialogs = []
    monkeypatch.setattr("app.gui.main_window.messagebox.showinfo", lambda *args: dialogs.append(args))
    monkeypatch.setattr("app.gui.main_window.messagebox.showerror", lambda *args: pytest.fail(str(args)))
    monkeypatch.setattr("app.gui.main_window.messagebox.showwarning", lambda *args: pytest.fail(str(args)))
    # Native workers schedule completion through Tk's main loop.
    root.after(50, window.build)
    deadline = time.monotonic() + 15

    def finished():
        if dialogs or time.monotonic() > deadline:
            root.quit()
        else:
            root.after(25, finished)

    root.after(100, finished)
    root.mainloop()
    assert dialogs, "Native GUI build did not complete"
    assert not window._busy
    assert window.build_button.cget("state") == "normal"
    assert (tmp_path / "delivery" / "license.dat").is_file()
    assert (project / "app/Service/Core.php").read_text(encoding="utf-8") == "<?php return 42;\n"
    assert (tmp_path / "delivery/app/Service/Other.php").read_text(encoding="utf-8") == "<?php return 7;\n"
    archive_path, = tmp_path.glob("delivery-*-Linux安装包.zip")
    with zipfile.ZipFile(archive_path) as archive:
        assert "--with-php-config=" in archive.read("LicenseProtector-Linux-Installer/native/build-linux.sh").decode()
        assert 'PHP_INI=""' in archive.read("LicenseProtector-Linux-Installer/install.sh").decode()
        assert not any("vendor_private" in item for item in archive.namelist())
