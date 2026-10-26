"""Windows clipboard sensor (Win32, post-hoc — race documented)."""
from __future__ import annotations

import ctypes
import threading
from typing import Optional

from ..core.store import Store
from ..privacy_guard.service import PrivacyService

_CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


class ClipboardSensor:
    def __init__(self, store: Store, privacy: PrivacyService):
        self.store = store
        self.privacy = privacy
        cfg = store.settings.get("privacy.clipboard_watch", {})
        self.interval = float(cfg.get("interval_ms", 700)) / 1000.0
        self._seq = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.last_error: str | None = None

    @staticmethod
    def _windows() -> bool:
        return hasattr(ctypes, "windll")

    def _read(self) -> str | None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        if not user32.OpenClipboard(None):
            return None
        try:
            if not user32.IsClipboardFormatAvailable(_CF_UNICODETEXT):
                return None
            handle = user32.GetClipboardData(_CF_UNICODETEXT)
            if not handle:
                return None
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.c_wchar_p(ptr).value or ""
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

    def _handle(self, text: str | None) -> None:
        if text is None:
            self.store.beat_sensor("clipboard", "degraded",
                                   "clipboard busy/locked by another process")
            return
        self.privacy.evaluate(text, context="clipboard",
                                       actor="clipboard:user")
        self.store.beat_sensor("clipboard", "up")

    def _run(self) -> None:
        self._seq = int(ctypes.windll.user32.GetClipboardSequenceNumber())
        while not self._stop.is_set():
            try:
                seq = int(ctypes.windll.user32.GetClipboardSequenceNumber())
                if seq != self._seq:
                    self._seq = seq
                    self._handle(self._read())
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.store.beat_sensor("clipboard", "down", self.last_error)
            self._stop.wait(self.interval)

    def start(self) -> bool:
        if not self._windows():
            self.last_error = "Windows-only sensor"
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="tw-clipboard")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
