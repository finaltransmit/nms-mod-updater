"""ModUpdater - keeps the mods that are git clones up to date while the game runs (NMS.py / pyMHF mod).

Every few seconds (setting, default 10 s) it looks at each git clone in the NMS.py mod folder (each folder next to
this one with a .git, a submodule included) and fetches its branch from origin:
  - nothing new: nothing happens;
  - new commits and a clean working tree: fast-forward to them;
  - local changes, or a history that went its own way: with "Overwrite local changes" on (the default) the local
    state is kept safe first (changed files in a git stash, local commits on a branch mod_updater/backup-<time>),
    then the clone is reset to origin's branch; with it off, that clone is skipped and the log says why;
  - local commits that origin doesn't have yet (a developer's unpushed work): left alone.
Changed mod files then reload through AutoReload (autoreload.py, next to this file), like saving a file in an editor;
a mod file that is new in the update is loaded into the running game. A deleted mod needs a game restart.

Private repos: the clone carries its own credentials, e.g. `git config core.sshCommand "ssh -i <deploy key>"`
(Setup.bat sets that up). Settings: the ModUpdater tab of the NMS.py window, saved to mod_updater.json next to this
file. Needs Git for Windows (git on PATH, or its usual install folder). Writes mod_updater.log next to this file.
"""
from __future__ import annotations

import json
import logging
import os
import os.path as op
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from pymhf import Mod, ModState
from pymhf.core.mod_loader import mod_manager
from pymhf.gui.decorators import BOOLEAN, FLOAT, STRING, gui_button

HERE = op.dirname(op.abspath(__file__))
MOD_DIR = op.dirname(HERE)
SETTINGS_FILE = op.join(HERE, "mod_updater.json")
DEFAULTS = {"enabled": True, "interval_s": 10.0, "overwrite_local_changes": True, "branch": "main"}
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: no console flashing up for each git call

logger = logging.getLogger("ModUpdater")
logger.propagate = True
if not any(getattr(h, "name", "") == "mod_updater_file" for h in logger.handlers):
    try:
        _fh = logging.FileHandler(op.join(HERE, "mod_updater.log"), encoding="utf-8")
        _fh.name = "mod_updater_file"
        _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        logger.addHandler(_fh)
    except OSError:
        pass


def load_settings() -> dict:
    s = dict(DEFAULTS)
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except (OSError, ValueError):
        save_settings(s)
    s["interval_s"] = max(2.0, float(s["interval_s"]))
    return s


def save_settings(s: dict) -> None:
    try:
        with open(SETTINGS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump({k: s[k] for k in DEFAULTS}, f, indent=2)
        os.replace(SETTINGS_FILE + ".tmp", SETTINGS_FILE)
    except OSError:
        logger.exception("could not save %s", SETTINGS_FILE)


def find_git() -> str | None:
    g = shutil.which("git")
    if g:
        return g
    for p in (r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files (x86)\Git\cmd\git.exe",
              op.join(os.environ.get("LOCALAPPDATA", ""), r"Programs\Git\cmd\git.exe")):
        if op.isfile(p):
            return p
    return None


def git(repo: str, *args, timeout: float = 60.0) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # never wait for a password prompt
    return subprocess.run([GIT, "-C", repo, *args], capture_output=True, text=True, timeout=timeout, env=env,
                          creationflags=NO_WINDOW)


GIT = find_git()


def clones() -> list[str]:
    """The mod folders that are git clones (a .git folder, or a .git file for a submodule)."""
    out = []
    for name in sorted(os.listdir(MOD_DIR)):
        p = op.join(MOD_DIR, name)
        if op.isdir(p) and op.exists(op.join(p, ".git")):
            out.append(p)
    return out


def _mod_files(repo: str, names) -> list[str]:
    """Top-level .py files among the changed paths that define a pyMHF mod (pyMHF loads one folder level)."""
    out = []
    for n in names:
        if "/" in n or not n.endswith(".py"):
            continue
        p = op.join(repo, n)
        try:
            if re.search(r"^class\s+\w+\s*\(\s*Mod\s*\)", open(p, encoding="utf-8").read(), re.M):
                out.append(p)
        except OSError:
            pass
    return out


def update(repo: str, settings: dict) -> str | None:
    """One clone: fetch, then fast-forward or (allowed) reset to origin. Returns a log line when something changed
    or was skipped, None when it was already up to date."""
    name = op.basename(repo)
    branch = settings["branch"]
    r = git(repo, "fetch", "--quiet", "origin", branch)
    if r.returncode:
        return f"{name}: fetch failed: {r.stderr.strip()[:200]}"
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    remote = git(repo, "rev-parse", f"origin/{branch}").stdout.strip()
    if not remote or head == remote:
        return None
    if git(repo, "merge-base", "--is-ancestor", remote, head).returncode == 0:
        return None  # we are ahead: unpushed local commits, nothing to take
    dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=no").stdout.strip())
    behind_only = git(repo, "merge-base", "--is-ancestor", head, remote).returncode == 0
    if behind_only and not dirty:
        r = git(repo, "merge", "--ff-only", "--quiet", f"origin/{branch}")
        if r.returncode:
            return f"{name}: fast-forward failed: {r.stderr.strip()[:200]}"
        how = "updated"
    elif not settings["overwrite_local_changes"]:
        return (f"{name}: origin/{branch} has new commits, but the clone has "
                f"{'local changes' if dirty else 'its own commits'}; skipped (Overwrite local changes is off)")
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if dirty:
            git(repo, "stash", "push", "--quiet", "-m", f"mod_updater {stamp}")
        if not behind_only:
            git(repo, "branch", f"mod_updater/backup-{stamp}", head)
        r = git(repo, "reset", "--hard", "--quiet", f"origin/{branch}")
        if r.returncode:
            return f"{name}: reset failed: {r.stderr.strip()[:200]}"
        kept = (["local changes stashed"] if dirty else []) + \
            ([f"local commits on mod_updater/backup-{stamp}"] if not behind_only else [])
        how = f"reset to origin ({'; '.join(kept)})"
    changed = git(repo, "diff", "--name-only", head, remote).stdout.split()
    _load_new_mods(repo, changed)
    return f"{name}: {head[:7]} -> {remote[:7]}, {how}; {len(changed)} files changed"


def _load_new_mods(repo: str, changed):
    """A mod file that wasn't loaded before (new in this update) is loaded now; changed ones AutoReload reloads."""
    loaded = {op.normcase(op.abspath(getattr(m, "__file__", "") or "")) for m in mod_manager._mod_paths.values()}
    for path in _mod_files(repo, changed):
        if op.normcase(op.abspath(path)) in loaded:
            continue
        try:
            gui = next((getattr(m, "pymhf_gui", None) for m in mod_manager.mods.values()
                        if getattr(m, "pymhf_gui", None)), None)
            before = set(mod_manager.mods)
            mod_manager._preloaded_mods.clear()
            mod_manager.load_mod(path)
            try:
                for mname, cls in list(mod_manager._preloaded_mods.items()):
                    if mname in before:
                        continue
                    mod = mod_manager.instantiate_mod(cls)
                    if mod is not None and gui is not None:
                        gui.add_tab(mod)
            finally:
                mod_manager._preloaded_mods.clear()
            mod_manager.hook_manager.initialize_hooks()
            logger.info("loaded new mod %s: %s", op.basename(path), sorted(set(mod_manager.mods) - before))
        except Exception:
            logger.exception("loading the new mod %s failed (restart the game to load it)", path)


@dataclass
class UpdaterState(ModState):
    thread_started: bool = False
    last: str = "-"


class ModUpdater(Mod):
    __author__ = "Traveller"
    __description__ = "Keeps git-cloned mods up to date and reloads them"
    __version__ = "1.0"

    state = UpdaterState()

    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        if not hasattr(sys, "_mod_updater_wake"):  # (one event for the loop thread, across reloads)
            sys._mod_updater_wake = threading.Event()
        if GIT is None:
            self.state.last = "Git for Windows not found: no updates"
            logger.warning(self.state.last)
        elif not self.state.thread_started:
            self.state.thread_started = True
            threading.Thread(target=self._loop, name="mod-updater", daemon=True).start()
            logger.info("watching %s every %.0f s: %s", MOD_DIR, self.settings["interval_s"],
                        ", ".join(op.basename(c) for c in clones()) or "no git clones yet")

    def _loop(self):
        while True:
            s = load_settings()  # (picks up changes from the GUI or the file)
            if s["enabled"]:
                for repo in clones():
                    try:
                        line = update(repo, s)
                    except Exception as e:
                        line = f"{op.basename(repo)}: {type(e).__name__}: {e}"
                    if line:
                        logger.info(line)
                        self.state.last = time.strftime("%H:%M:%S ") + line[:120]
            sys._mod_updater_wake.wait(s["interval_s"])
            sys._mod_updater_wake.clear()

    # ------------------------------------------------------------------ GUI ----
    @property
    @BOOLEAN("Enabled")
    def enabled(self):
        return load_settings()["enabled"]

    @enabled.setter
    def enabled(self, value: bool):
        s = load_settings()
        s["enabled"] = bool(value)
        save_settings(s)

    @property
    @FLOAT("Check every (s)", min_value=2.0, max_value=3600.0, min_clamped=True, max_clamped=True)
    def interval_s(self):
        return load_settings()["interval_s"]

    @interval_s.setter
    def interval_s(self, value: float):
        s = load_settings()
        s["interval_s"] = max(2.0, float(value))
        save_settings(s)

    @property
    @BOOLEAN("Overwrite local changes (stashed first)")
    def overwrite(self):
        return load_settings()["overwrite_local_changes"]

    @overwrite.setter
    def overwrite(self, value: bool):
        s = load_settings()
        s["overwrite_local_changes"] = bool(value)
        save_settings(s)

    @property
    @STRING("Last update")
    def last(self):
        return self.state.last

    @gui_button("Check now")
    def check_now(self):
        sys._mod_updater_wake.set()
