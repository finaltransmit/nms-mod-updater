"""AutoReload - reloads any other loaded mod when its .py file changes on disk.

This removes the need to press "Reload" in the pyMHF GUI after editing a mod. It polls file
modification times from a background thread (never from the game thread) and uses the same code
path as the GUI's Reload button. It will not reload itself; restart the game to change this file.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import os.path as op
import threading
import time
from dataclasses import dataclass, field

from pymhf import Mod, ModState
from pymhf.core.mod_loader import mod_manager
from pymhf.gui.decorators import BOOLEAN, INTEGER, STRING

logger = logging.getLogger("AutoReload")

POLL_SECONDS = 1.0
SETTLE_SECONDS = 0.5  # wait for the editor to finish writing before reloading


def decouple_socket_logging() -> int:
    """pyMHF forwards the game's log records to its console through a logging SocketHandler (localhost:9020) on
    whatever thread logs. Once that console is gone, the handler retries every 30 s and each retry blocks the
    logging thread ~2 s (1 s connect timeout per address of 'localhost': ::1, then 127.0.0.1). When that thread is
    the game's update thread, the main thread waits on it and the whole game freezes 2 s every ~31 s. Hand the
    SocketHandler to a QueueListener thread so game threads only ever enqueue."""
    root = logging.getLogger()
    moved = 0
    for h in list(root.handlers):
        if isinstance(h, logging.handlers.SocketHandler):
            q = queue.SimpleQueue()
            qh = logging.handlers.QueueHandler(q)
            qh.setLevel(h.level)
            listener = logging.handlers.QueueListener(q, h, respect_handler_level=True)
            listener.start()
            listener._thread.name = "pymhf-log-forwarder"
            qh.listener = listener
            root.addHandler(qh)
            root.removeHandler(h)
            moved += 1
    return moved


@dataclass
class ReloadState(ModState):
    thread_started: bool = False
    mtimes: dict = field(default_factory=dict)
    reloads: int = 0
    last_reloaded: str = "-"
    enabled: bool = True


class AutoReload(Mod):
    __author__ = "Traveller"
    __description__ = "Hot-reloads mods whose source file changed on disk"
    __version__ = "0.1"

    state = ReloadState()

    def __init__(self):
        super().__init__()
        if decouple_socket_logging():
            logger.info("AutoReload: console log forwarding moved off the game threads")
        if not self.state.thread_started:
            self.state.thread_started = True
            t = threading.Thread(target=self._poll_loop, name="pymhf-autoreload", daemon=True)
            t.start()
            logger.info("AutoReload: watching mod files for changes")

    # ---------------------------------------------------------------------------- GUI ----
    @property
    @BOOLEAN("Enabled")
    def enabled(self):
        return self.state.enabled

    @enabled.setter
    def enabled(self, value: bool):
        self.state.enabled = value

    @property
    @INTEGER("Reloads performed")
    def reloads(self):
        return self.state.reloads

    @property
    @STRING("Last reloaded")
    def last_reloaded(self):
        return self.state.last_reloaded

    # ------------------------------------------------------------------------- worker ----
    def _mod_files(self) -> dict[str, str]:
        """name -> file path for every loaded mod except this one."""
        out = {}
        for name, module in list(mod_manager._mod_paths.items()):
            if name == self._mod_name:
                continue
            f = getattr(module, "__file__", None)
            if f and op.isfile(f):
                out[name] = f
        return out

    def _poll_loop(self):
        # Prime the mtimes so the first pass doesn't reload everything.
        for name, f in self._mod_files().items():
            self.state.mtimes.setdefault(name, os.stat(f).st_mtime)
        while True:
            time.sleep(POLL_SECONDS)
            try:
                if not self.state.enabled:
                    continue
                for name, f in self._mod_files().items():
                    mtime = os.stat(f).st_mtime
                    old = self.state.mtimes.get(name)
                    if old is None:
                        self.state.mtimes[name] = mtime
                        continue
                    if mtime != old:
                        # Wait until the file stops changing.
                        time.sleep(SETTLE_SECONDS)
                        mtime = os.stat(f).st_mtime
                        self.state.mtimes[name] = mtime
                        self._reload(name, f)
            except Exception:
                logger.exception("AutoReload poll failed")

    def _reload(self, name: str, f: str):
        gui = self.pymhf_gui
        if gui is None:
            logger.warning("AutoReload: no GUI instance; cannot reload %s", name)
            return
        logger.info("AutoReload: %s changed -> reloading %s", op.basename(f), name)
        self._guard_reload_tab(gui)
        try:
            # Same path the GUI's Reload button takes (pyMHF 0.2.4: _gui_reload; 0.2.5 removed it, its button
            # calls mod_manager.reload(name), which logs its own errors instead of raising).
            if hasattr(mod_manager, "_gui_reload"):
                mod_manager._gui_reload(None, None, (name, gui))
            else:
                mod_manager.reload(name)
            self.state.reloads += 1
            self.state.last_reloaded = f"{name} @ {time.strftime('%H:%M:%S')}"
            stale = self._purge_stale(name)
            logger.info("AutoReload: %s reloaded%s", name, f" ({stale} stale detours removed)" if stale else "")
        except Exception:
            logger.exception("AutoReload: reloading %s failed", name)

    @staticmethod
    def _guard_reload_tab(gui):
        """Mods hot-added with mod_manager.load_single_mod() have no GUI tab: pyMHF's reload then raises in
        gui.reload_tab() before it clears mod_manager._preloaded_mods, and every later reload re-instantiates the
        leftovers and dies the same way (one mod stops reloading, another gets re-created on every reload).
        Swallow that error and drop stale preloaded mods before each reload."""
        mod_manager._preloaded_mods.clear()
        if getattr(gui, "_safe_reload_tab", False):
            return
        orig = gui.reload_tab

        def safe_reload_tab(mod, _orig=orig):
            try:
                _orig(mod)
            except Exception as e:
                logger.warning("reload_tab(%s) failed (mod has no GUI tab?): %s", type(mod).__name__, e)

        gui.reload_tab = safe_reload_tab
        gui._safe_reload_tab = True

    @staticmethod
    def _purge_stale(name: str) -> int:
        """pyMHF's reload can leave the old instance's detours attached (NMS.py-style cGcPlayer::Update hooks can
        stay while manual hooks are removed), so the old copy keeps running every frame. Drop every detour bound
        to an older instance of the reloaded mod's class."""
        current = mod_manager.mods.get(name)
        if current is None:
            return 0
        cls_name = type(current).__name__
        removed = 0
        for hook in list(mod_manager.hook_manager.hooks.values()):
            for attr in ("_before_detours", "_after_detours", "_after_detours_with_results"):
                detours = getattr(hook, attr, None)
                if not detours:
                    continue
                for d in list(detours):
                    owner = getattr(d, "__self__", None)
                    if owner is not None and owner is not current and type(owner).__name__ == cls_name:
                        detours.remove(d)
                        removed += 1
        return removed
