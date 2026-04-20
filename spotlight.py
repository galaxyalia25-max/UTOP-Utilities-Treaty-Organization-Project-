import os
import sys
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple

try:
    from PyQt6 import QtCore, QtGui, QtWidgets
except Exception:
    print("Missing dependency: PyQt6. Install with: pip install PyQt6")
    raise

try:
    from pynput import keyboard  # type: ignore
except Exception:
    keyboard = None

try:
    import win32com.client  # type: ignore
except Exception:
    win32com = None


@dataclass(frozen=True)
class AppEntry:
    name: str
    launch: str
    icon_source: Optional[str]
    is_uwp: bool


def _expand_env(p: str) -> str:
    return os.path.expandvars(p)


def _start_menu_dirs() -> List[str]:
    dirs = []
    for p in [
        r"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
        r"%AppData%\Microsoft\Windows\Start Menu\Programs",
    ]:
        ep = _expand_env(p)
        if os.path.isdir(ep):
            dirs.append(ep)
    return dirs


def _norm_key(s: str) -> str:
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def _display_name_from_filename(path: str) -> str:
    base = os.path.basename(path)
    name, _ = os.path.splitext(base)
    name = name.replace(" - Shortcut", "").strip()
    name = re.sub(r"\s+", " ", name)
    return name if name else base


def _iter_shortcut_files() -> List[str]:
    out = []
    for d in _start_menu_dirs():
        for root, _, files in os.walk(d):
            for f in files:
                lf = f.lower()
                if lf.endswith(".lnk") or lf.endswith(".appref-ms"):
                    out.append(os.path.join(root, f))
    return out


def _resolve_lnk(path: str) -> Tuple[Optional[str], Optional[str]]:
    if win32com is None:
        return None, None
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        sc = shell.CreateShortcut(path)
        target = getattr(sc, "TargetPath", None) or None
        args = getattr(sc, "Arguments", None) or ""
        icon = getattr(sc, "IconLocation", None) or None
        if target and args:
            return f"\"{target}\" {args}".strip(), icon
        return (f"\"{target}\"".strip() if target else None), icon
    except Exception:
        return None, None


def _build_app_list() -> List[AppEntry]:
    seen: Dict[str, AppEntry] = {}
    files = _iter_shortcut_files()
    for p in files:
        name = _display_name_from_filename(p)
        key = _norm_key(name)
        if not key:
            continue
        lp = p.lower()
        if lp.endswith(".appref-ms"):
            launch = p
            icon_source = p
            entry = AppEntry(name=name, launch=launch, icon_source=icon_source, is_uwp=False)
            if key not in seen:
                seen[key] = entry
            continue
        if lp.endswith(".lnk"):
            launch, icon = _resolve_lnk(p)
            if not launch:
                launch = p
            icon_source = p
            entry = AppEntry(name=name, launch=launch, icon_source=icon_source, is_uwp=False)
            if key not in seen:
                seen[key] = entry
            continue
    entries = list(seen.values())
    entries.sort(key=lambda e: e.name.lower())
    return entries


def _score(query: str, name: str) -> Optional[Tuple[int, int]]:
    q = query.strip().lower()
    if not q:
        return (10_000, 0)
    n = name.lower()
    if n == q:
        return (0, 0)
    if n.startswith(q):
        return (1, len(n))
    if q in n:
        return (2, n.find(q))
    qi = 0
    last = -1
    for ch in q:
        idx = n.find(ch, last + 1)
        if idx < 0:
            return None
        last = idx
        qi += 1
    return (3, last)


class _IconProvider:
    def __init__(self):
        self._provider = QtWidgets.QFileIconProvider()

    def icon_for_path(self, path: str) -> Optional[QtGui.QIcon]:
        try:
            if not path:
                return None
            fi = QtCore.QFileInfo(path)
            ic = self._provider.icon(fi)
            if ic is None or ic.isNull():
                return None
            return ic
        except Exception:
            return None


class _FadeMask(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._top = 18
        self._bottom = 22
        self._base = QtGui.QColor(16, 16, 16, 120)

    def paintEvent(self, event):
        w = self.width()
        h = self.height()
        if w <= 0 or h <= 0:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, False)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        if self._top > 0:
            g = QtGui.QLinearGradient(0, 0, 0, self._top)
            c0 = QtGui.QColor(self._base)
            c1 = QtGui.QColor(self._base)
            c0.setAlpha(min(220, self._base.alpha() + 120))
            c1.setAlpha(0)
            g.setColorAt(0.0, c0)
            g.setColorAt(1.0, c1)
            p.setBrush(g)
            p.drawRect(0, 0, w, self._top)
        if self._bottom > 0:
            g = QtGui.QLinearGradient(0, h - self._bottom, 0, h)
            c0 = QtGui.QColor(self._base)
            c1 = QtGui.QColor(self._base)
            c0.setAlpha(0)
            c1.setAlpha(min(230, self._base.alpha() + 140))
            g.setColorAt(0.0, c0)
            g.setColorAt(1.0, c1)
            p.setBrush(g)
            p.drawRect(0, h - self._bottom, w, self._bottom)
        p.end()


class SpotlightWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Spotlight")
        self.setWindowFlags(
            QtCore.Qt.WindowType.FramelessWindowHint
            | QtCore.Qt.WindowType.Tool
            | QtCore.Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_ShowWithoutActivating, False)

        self._apps: List[AppEntry] = []
        self._icon_cache: Dict[str, QtGui.QIcon] = {}
        self._icons = _IconProvider()

        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(10)

        self.card = QtWidgets.QFrame()
        self.card.setObjectName("card")
        card_layout = QtWidgets.QVBoxLayout(self.card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(10)

        self.input = QtWidgets.QLineEdit()
        self.input.setPlaceholderText("Search apps…")
        self.input.setClearButtonEnabled(True)
        self.input.textChanged.connect(self._refresh_results)
        self.input.returnPressed.connect(self._launch_selected)

        self.list = QtWidgets.QListWidget()
        self.list.setUniformItemSizes(True)
        self.list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.list.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.itemActivated.connect(self._launch_selected)
        self.list.setIconSize(QtCore.QSize(22, 22))
        try:
            vp = self.list.viewport()
            vp.setAutoFillBackground(True)
            pal = vp.palette()
            pal.setColor(vp.backgroundRole(), QtGui.QColor(16, 16, 16, 1))
            vp.setPalette(pal)
            self.list.verticalScrollBar().valueChanged.connect(lambda _: vp.update())
        except Exception:
            pass

        card_layout.addWidget(self.input)
        list_wrap = QtWidgets.QWidget()
        stack = QtWidgets.QStackedLayout(list_wrap)
        stack.setStackingMode(QtWidgets.QStackedLayout.StackingMode.StackAll)
        stack.setContentsMargins(0, 0, 0, 0)
        stack.addWidget(self.list)
        self._mask = _FadeMask()
        stack.addWidget(self._mask)
        card_layout.addWidget(list_wrap)
        outer.addWidget(self.card)

        self._apply_styles()

        self._reload_timer = QtCore.QTimer(self)
        self._reload_timer.setSingleShot(True)
        self._reload_timer.timeout.connect(self._reload_apps)
        self._reload_timer.start(0)

    def _apply_styles(self):
        self.setStyleSheet(
            """
            QWidget { color: rgba(255,255,255,235); font-size: 14px; }
            #card {
              background: rgba(16,16,16,120);
              border: 1px solid rgba(255,255,255,60);
              border-radius: 18px;
            }
            QLineEdit {
              background: rgba(255,255,255,18);
              border: 1px solid rgba(255,255,255,45);
              border-radius: 14px;
              padding: 10px 12px;
              font-size: 15px;
              selection-background-color: rgba(255,255,255,70);
            }
            QListWidget {
              background: transparent;
              border: none;
              outline: none;
            }
            QListWidget::item {
              padding: 10px 10px;
              border-radius: 12px;
            }
            QListWidget::item:selected {
              background: rgba(255,255,255,22);
              border: 1px solid rgba(255,255,255,45);
            }
            """
        )

    def show_centered(self):
        scr = QtGui.QGuiApplication.primaryScreen()
        geo = scr.availableGeometry() if scr else QtCore.QRect(0, 0, 1200, 800)
        w = min(640, geo.width() - 80)
        h = min(520, geo.height() - 120)
        self.resize(w, h)
        self.move(geo.x() + (geo.width() - w) // 2, geo.y() + (geo.height() - h) // 2)
        self.show()
        self.raise_()
        self.activateWindow()
        self.input.setFocus()
        self.input.selectAll()

    def hide_and_clear(self):
        self.hide()
        self.input.setText("")

    def toggle(self):
        if self.isVisible():
            self.hide_and_clear()
        else:
            self.show_centered()

    def _reload_apps(self):
        self._apps = _build_app_list()
        self._refresh_results()

    def _icon_for(self, e: AppEntry) -> QtGui.QIcon:
        key = e.icon_source or e.launch
        if key in self._icon_cache:
            return self._icon_cache[key]
        icon = None
        if e.icon_source:
            icon = self._icons.icon_for_path(e.icon_source)
        if icon is None:
            try:
                icon = QtGui.QIcon.fromTheme("application-x-executable")
            except Exception:
                icon = None
        if icon is None or icon.isNull():
            pm = QtGui.QPixmap(22, 22)
            pm.fill(QtCore.Qt.GlobalColor.transparent)
            p = QtGui.QPainter(pm)
            p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.setBrush(QtGui.QColor(255, 255, 255, 70))
            p.drawEllipse(1, 1, 20, 20)
            p.end()
            icon = QtGui.QIcon(pm)
        self._icon_cache[key] = icon
        return icon

    def _refresh_results(self):
        q = self.input.text()
        scored = []
        for e in self._apps:
            s = _score(q, e.name)
            if s is None:
                continue
            scored.append((s, e))
        scored.sort(key=lambda t: (t[0][0], t[0][1], t[1].name.lower()))
        self.list.clear()
        for _, e in scored[:60]:
            it = QtWidgets.QListWidgetItem(e.name)
            it.setData(QtCore.Qt.ItemDataRole.UserRole, e)
            it.setIcon(self._icon_for(e))
            self.list.addItem(it)
        if self.list.count() > 0:
            self.list.setCurrentRow(0)

    def _selected_entry(self) -> Optional[AppEntry]:
        it = self.list.currentItem()
        if not it:
            return None
        e = it.data(QtCore.Qt.ItemDataRole.UserRole)
        return e if isinstance(e, AppEntry) else None

    def _launch_selected(self):
        e = self._selected_entry()
        if not e:
            return
        self.hide_and_clear()
        try:
            if e.launch.lower().endswith(".appref-ms"):
                os.startfile(e.launch)
                return
            if e.launch.lower().endswith(".lnk"):
                os.startfile(e.launch)
                return
            if e.launch.startswith("\"") and "\"" in e.launch[1:]:
                subprocess.Popen(e.launch, shell=True)
                return
            subprocess.Popen(e.launch, shell=True)
        except Exception:
            try:
                os.startfile(e.launch)
            except Exception:
                return

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.hide_and_clear()
            return
        if event.key() == QtCore.Qt.Key.Key_Down:
            r = min(self.list.currentRow() + 1, self.list.count() - 1)
            if r >= 0:
                self.list.setCurrentRow(r)
            return
        if event.key() == QtCore.Qt.Key.Key_Up:
            r = max(self.list.currentRow() - 1, 0)
            self.list.setCurrentRow(r)
            return
        super().keyPressEvent(event)


class Tray(QtWidgets.QSystemTrayIcon):
    def __init__(self, window: SpotlightWindow):
        super().__init__()
        self.window = window
        pm = QtGui.QPixmap(64, 64)
        pm.fill(QtCore.Qt.GlobalColor.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(QtGui.QColor(255, 255, 255, 200))
        p.drawEllipse(8, 8, 48, 48)
        p.setBrush(QtGui.QColor(16, 16, 16, 220))
        p.drawEllipse(18, 18, 28, 28)
        p.setBrush(QtGui.QColor(255, 255, 255, 200))
        p.drawEllipse(41, 41, 8, 8)
        p.end()
        self.setIcon(QtGui.QIcon(pm))
        menu = QtWidgets.QMenu()
        a_show = menu.addAction("Toggle (Ctrl+Space)")
        a_show.triggered.connect(self.window.toggle)
        a_reload = menu.addAction("Reload apps")
        a_reload.triggered.connect(self.window._reload_apps)
        menu.addSeparator()
        a_quit = menu.addAction("Quit")
        a_quit.triggered.connect(QtWidgets.QApplication.quit)
        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.ActivationReason.Trigger:
            self.window.toggle()


def main():
    if os.name != "nt":
        print("This app is Windows-only.")
        return
    if keyboard is None:
        print("Missing dependency: pynput. Install with: pip install pynput")
        return
    app = QtWidgets.QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    win = SpotlightWindow()
    tray = Tray(win)
    tray.show()

    class Bridge(QtCore.QObject):
        toggled = QtCore.pyqtSignal()

    bridge = Bridge()
    bridge.toggled.connect(win.toggle)

    def hotkey_thread():
        state = {"ctrl": False}

        def on_press(k):
            try:
                if k in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
                    state["ctrl"] = True
                if state["ctrl"] and (k == keyboard.Key.space or getattr(k, "char", None) == " "):
                    bridge.toggled.emit()
            except Exception:
                return

        def on_release(k):
            try:
                if k in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
                    state["ctrl"] = False
            except Exception:
                return

        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

    t = threading.Thread(target=hotkey_thread, daemon=True)
    t.start()

    rc = app.exec()
    sys.exit(rc)


if __name__ == "__main__":
    main()