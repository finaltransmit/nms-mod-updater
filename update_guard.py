"""UpdateGuard - keeps the NMS.py hooks the other mods hang on pointing at the right functions after a game update.

NMS.py finds a function to hook by one byte pattern and takes pyMHF's first match, with no check that the pattern
still matches exactly one function (or any) on a new game build. Sixteen of our hooks sit on cGcPlayer::Update alone
(every "game thread" callback), nmspy's own state tracking on cTkFSM::StateChange. Should such a pattern stop
matching, those hooks would silently never run; should it match some other function first, they would run in the
wrong place.

This mod carries the same address lookup as the other mods (several patterns per function, call sites included,
all must agree) for those functions. At import, before pyMHF registers any hook (every mod file is imported first,
hooks are registered after), it compares: when NMS.py's own pattern finds exactly the function we found, nothing
happens; otherwise the offset we found is put into pyMHF's offset cache under NMS.py's pattern string, which is
what pyMHF consults first, so the hooks land where they belong. Nothing is written to disk for pyMHF (in-memory
only); the outcome is logged and written to update_guard.status.json next to this file.

Patterns come from build 180836; they are chosen to survive small compiler shuffles (each function's prologue plus
a caller's call site). tools/check_addresses.py checks them offline against any NMS.exe, tools/update_preflight.py
runs that for every mod after an update.
"""
from __future__ import annotations

import json
import logging
import os.path as op
import re
import sys
import time

logger = logging.getLogger("UpdateGuard")
HERE = op.dirname(op.abspath(__file__))
STATUS_FILE = op.join(HERE, "update_guard.status.json")

# >>> nms-address-lookup (shared block: keep identical in every mod; tools/check_addresses.py runs it offline) >>>
# Build-specific addresses are looked up in the running NMS.exe by masked byte patterns, so a game update does not
# need a new mod release. Pattern tokens: "48" a byte, "?" any byte, "[2-8]" 2 to 8 any bytes, "* * * *" a rel32
# field (RIP-relative operand or call target: value = end of its instruction + rel32; several "*" fields in one
# pattern must agree), "# # # #" a u32 field (the value itself, e.g. a struct offset), ">" the end of the
# instruction holding the field when an immediate follows it, "^" the result position of a pattern without a
# field (default: its start), "@text" a rel32 that must point at the bytes "text" and "=NAME" a rel32 that must
# point at the address NAME found earlier in the same table (both pick the right one of look-alike sites).
# A pattern counts when all its matches give one value; the counting patterns must agree, and the value must pass
# its kind's check ("data": inside a writable data section, "code": a function start in executable code, plus an
# optional masked "prologue", "value": inside "range") and the optional live "check" ("ptr", "vft", "vft:<class>",
# "u32<N"; a null pointer passes). Nothing found -> 0 and a warning; the caller switches that feature off. Only on
# the build the "known" values were verified on (180836) is a failed lookup replaced by the known value.
import ctypes as _actypes
import re as _are
import sys as _asys

_ADDR_KNOWN_BUILD = (0x6ABE9229, 0x771D000)  # NMS.exe 180836: PE TimeDateStamp, SizeOfImage
_addr_k32 = _actypes.WinDLL("kernel32") if hasattr(_actypes, "WinDLL") else None
if _addr_k32 is not None:
    _addr_k32.GetCurrentProcess.restype = _actypes.c_void_p
    _addr_k32.ReadProcessMemory.argtypes = [_actypes.c_void_p, _actypes.c_void_p, _actypes.c_void_p,
                                            _actypes.c_size_t, _actypes.POINTER(_actypes.c_size_t)]


def _addr_peek(addr: int, n: int):
    """n bytes at an absolute address of this process, or None (never faults)."""
    out, got = _actypes.create_string_buffer(n), _actypes.c_size_t(0)
    if addr and _addr_k32.ReadProcessMemory(_addr_k32.GetCurrentProcess(), _actypes.c_void_p(addr), out, n,
                                            _actypes.byref(got)) and got.value == n:
        return out.raw
    return None


class _AddrImage:
    """Sections and bytes of NMS.exe: the running image (base given) or an exe file (offline checks). Code is read
    from the exe file when it is the running build: the same bytes, minus the mods' hooks and patches."""

    def __init__(self, base: int = 0, path: str = ""):
        import pefile
        self.base, self._file = base, None
        if base:
            head = _addr_peek(base, 0x1000)
            if head is None:
                raise RuntimeError("cannot read the PE header of the running image")
            pe = pefile.PE(data=head, fast_load=True)
        else:
            pe = self._file = pefile.PE(path, fast_load=True)
        self.build = (pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage)
        self.sections = [(s.Name.rstrip(b"\0").decode(errors="replace"), s.VirtualAddress, s.Misc_VirtualSize,
                          s.Characteristics) for s in pe.sections]
        if base and path:
            try:
                f = pefile.PE(path, fast_load=True)
                if (f.FILE_HEADER.TimeDateStamp, f.OPTIONAL_HEADER.SizeOfImage) == self.build:
                    self._file = f
            except Exception:
                pass
        self._text = None

    def section(self, rva: int):
        for name, va, size, chars in self.sections:
            if va <= rva < va + size:
                return name, chars
        return None, 0

    def read(self, rva: int, n: int):
        if self.section(rva)[0] is None or self.section(rva + n - 1)[0] is None:
            return None
        if self._file is None:
            return _addr_peek(self.base + rva, n)
        b = self._file.get_data(rva, n)
        return b + b"\0" * (n - len(b))  # uninitialised data reads as zeros

    def text(self):
        if self._text is None:
            _, va, size, _ = next(s for s in self.sections if s[0] == ".text")
            self._text = (va, self.read(va, size))
        return self._text


_ADDR_RX = {}


def _addr_compile(sig: str):
    """Pattern -> (regex, [field token per regex group], {field group: group of its instruction end})."""
    if sig in _ADDR_RX:
        return _ADDR_RX[sig]
    toks, rx, fields, ends, k, last = sig.split(), b"", [], {}, 0, 0
    while k < len(toks):
        t = toks[k]
        if t in ("*", "#"):
            if toks[k:k + 4] != [t] * 4:
                raise ValueError(f"'{t}' must come four in a row: {sig}")
            rx += b"(....)"
            fields.append(t)
            last = len(fields)
            k += 4
            continue
        if t[0] in "@=":
            rx += b"(....)"
            fields.append(t)
            last = len(fields)
        elif t in (">", "^"):
            rx += b"()"
            fields.append(t)
            if t == ">":
                ends[last] = len(fields)
        elif t == "?":
            rx += b"."
        elif t.startswith("["):
            lo, hi = t[1:-1].split("-")
            rx += b".{%d,%d}?" % (int(lo), int(hi))
        else:
            rx += _are.escape(bytes([int(t, 16)]))
        k += 1
    _ADDR_RX[sig] = out = (_are.compile(rx, _are.S), fields, ends)
    return out


def _addr_match_value(img, text_rva: int, m, fields, ends, env):
    """The value one match gives, or None (an @text/=NAME check failed, or its fields disagree)."""
    value, pos = None, None
    for g, f in enumerate(fields, 1):
        if f == "^":
            pos = text_rva + m.start(g)
        if f not in ("*", "#") and f[0] not in "@=":
            continue
        raw = int.from_bytes(m.group(g), "little", signed=f != "#")
        v = raw if f == "#" else text_rva + (m.start(ends[g]) if g in ends else m.end(g)) + raw
        if f.startswith("@"):
            want = f[1:].encode()
            if img.read(v, len(want)) != want:
                return None
        elif f[0] == "=":
            if not env.get(f[1:]) or env[f[1:]] != v:
                return None
        elif value is None:
            value = v
        elif value != v:
            return None
    if value is None:
        value = pos if pos is not None else text_rva + m.start()
    return value


def _addr_scan(img, sig: str, env: dict):
    """Set of values the pattern's matches give in .text (cached per build across mods)."""
    cache = getattr(_asys, "_nms_addr_scan_cache", None)
    if cache is None:
        cache = {}
        setattr(_asys, "_nms_addr_scan_cache", cache)
    rx, fields, ends = _addr_compile(sig)
    key = (img.build, sig) + tuple(env.get(f[1:]) for f in fields if f[0] == "=")
    if key not in cache:
        text_rva, text = img.text()
        vals = {_addr_match_value(img, text_rva, m, fields, ends, env) for m in rx.finditer(text)}
        vals.discard(None)
        cache[key] = frozenset(vals)
    return cache[key]


def _addr_live_check(img, check: str, rva: int):
    """None if the live value at NMS+rva passes `check`, else what is wrong."""
    def u64(a):
        b = _addr_peek(a, 8)
        return int.from_bytes(b, "little") if b else None
    slot = img.base + rva
    if check.startswith("u32<"):
        b = _addr_peek(slot, 4)
        v = int.from_bytes(b, "little") if b else None
        return None if v is not None and v < int(check[4:], 0) else f"value {v} not {check[3:]}"
    obj = u64(slot)
    if obj is None:
        return "slot unreadable"
    if not obj:
        return None  # not created yet: nothing to check
    if check == "ptr":
        return None if _addr_peek(obj, 8) is not None else f"points to unreadable {obj:#x}"
    vft = u64(obj)
    if vft is None:
        return f"points to unreadable {obj:#x}"
    name, chars = img.section(vft - img.base)
    if name is None or chars & 0xA0000000:  # executable or writable: not a vftable
        return f"object {obj:#x} has no vftable in the image"
    if check.startswith("vft:"):
        col = u64(vft - 8)
        hdr = _addr_peek(col, 16) if col else None
        td = int.from_bytes(hdr[12:16], "little") if hdr else 0
        want = (".?AV" + check[4:] + "@@\0").encode()
        if not td or _addr_peek(img.base + td + 16, len(want)) != want:
            return f"object {obj:#x} is not a {check[4:]}"
    return None


def _addr_check(img, spec: dict, v: int):
    """None if v is plausible for the spec's kind, else what is wrong."""
    kind = spec["kind"]
    if kind == "value":
        lo, hi = spec["range"]
        return None if lo <= v < hi else f"{v:#x} outside {lo:#x}..{hi:#x}"
    name, chars = img.section(v)
    if kind == "data":
        if name is None or not chars & 0x80000000 or chars & 0x20000000:
            return f"NMS+0x{v:X} is not in a writable data section ({name})"
    elif kind == "code":
        if name is None or not chars & 0x20000000:
            return f"NMS+0x{v:X} is not in executable code ({name})"
        before = img.read(v - 1, 1)
        if v & 0xF and before not in (b"\xcc", b"\xc3"):
            return f"NMS+0x{v:X} is not a function start"
        if spec.get("prologue"):
            rx = _addr_compile(spec["prologue"])[0]
            code = img.read(v, 64)
            if not code or not rx.match(code):
                return f"NMS+0x{v:X} does not start with the expected prologue"
    else:
        return f"unknown kind {kind!r}"
    if spec.get("check") and img.base:
        return _addr_live_check(img, spec["check"], v)
    return None


def _addr_lookup(img, spec: dict, env: dict):
    """(value or 0, problem or None, per-pattern notes)."""
    found, notes = set(), []
    for sig in spec["sigs"]:
        try:
            vals = _addr_scan(img, sig, env)
        except Exception as e:
            vals = frozenset()
            notes.append(f"error {e!r}")
            continue
        notes.append("1" if len(vals) == 1 else f"{len(vals)} values" if vals else "0")
        if len(vals) == 1:
            found |= vals
    if not found:
        return 0, "no pattern matched", notes
    if len(found) > 1:
        return 0, "patterns disagree: " + ", ".join(f"0x{v:X}" for v in sorted(found)), notes
    v = found.pop()
    problem = _addr_check(img, spec, v)
    return (0, problem, notes) if problem else (v, None, notes)


def _addr_resolve(specs: dict, log, img=None) -> dict:
    """{name: RVA ("data"/"code") or value ("value"), 0 when not found} for an ADDRESSES table."""
    out = {}
    try:
        if img is None:
            import pymhf.core._internal as _pi
            img = _AddrImage(base=_pi.BASE_ADDRESS, path=_pi.BINARY_PATH)
    except Exception:
        log.exception("address lookup: cannot read the game image")
        return {name: 0 for name in specs}
    known_build = img.build == _ADDR_KNOWN_BUILD
    for name, spec in specs.items():
        try:
            v, problem, notes = _addr_lookup(img, spec, out)
        except Exception as e:
            v, problem, notes = 0, f"lookup failed: {e!r}", []
        show = (lambda x: f"0x{x:X}") if spec["kind"] == "value" else (lambda x: f"NMS+0x{x:X}")
        if known_build and v != spec["known"]:
            log.warning("address %s: %s (patterns %s) - build 180836, so using its verified value %s", name,
                        problem or f"patterns give {show(v)}", "/".join(notes), show(spec["known"]))
            v = spec["known"]
        elif problem:
            log.warning("address %s not found: %s (patterns %s) - what needs it stays off", name, problem,
                        "/".join(notes))
        else:
            log.info("address %s = %s (patterns %s)", name, show(v), "/".join(notes))
        out[name] = v
    return out
# <<< nms-address-lookup <<<

# The NMS.py hooks the mods depend on: our own lookup for each (the function's prologue and a call site), and the
# nmspy class/method whose pattern pyMHF uses.
ADDRESSES = {
    # cGcPlayer::Update(this, float step): the game-thread tick every mod hooks (its one caller: the simulation's
    # player update, which picks the step with a cmove on the pause state)
    # (the 2026-10 build pushes one register more, rsi: hence "[0-2]" after push rbx)
    "PLAYER_UPDATE": {"kind": "code", "known": 0x144B3A0,
                      "prologue": "48 8B C4 48 89 48 ? 55 53 [0-2] 41 54 41 55 41 57 48 8D A8", "sigs": [
        "48 8B C4 48 89 48 08 55 53 [0-2] 41 54 41 55 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 44 0F 29 40 98 "
        "4C 8B F9 44 0F 29 48 88 44 0F 28 C1",
        "0F 44 05 ? ? ? ? 83 F8 04 74 ? 41 0F 28 CA 49 8B CE E8 * * * * 41 B0 01 4C 89 BC 24",
    ]},
    # cTkFSM::StateChange: NMS.py's _INTERNAL_LoadSingletons hooks it to find cGcApplication (gameData.*)
    "FSM_STATE_CHANGE": {"kind": "code", "known": 0x2BE4B00,
                         "prologue": "48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 4C 8B 51", "sigs": [
        "48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B 51 08 49 8B E8 4C 8B 1D ? ? ? ? 48 8B F9 48 8B 35 "
        "? ? ? ? 48 89 5C 24 30",
        "44 0F B6 49 30 48 8D 51 18 4C 8B 41 28 E8 * * * * 0F 10 05 ? ? ? ? 48 C7 43 28 00 00 00 00",
    ]},
    # cGcFrontendManager::Activate(this, page, bool): LiveScreen watches it
    "FRONTEND_ACTIVATE": {"kind": "code", "known": 0x8FE180, "prologue": "40 55 56 57 41 57 48 8B EC", "sigs": [
        "40 55 56 57 41 57 48 8B EC 48 83 EC 58 8B 81 ? ? ? ? 45 0F B6 F8 48 63 F2 48 8B F9 83 F8 04 74 10 85 C0 "
        "74 0C 32 C0 48 83 C4 58 41 5F 5F 5E 5D C3",
        "41 B0 01 BA 09 00 00 00 48 8B C8 E8 * * * * EB 1F 0F 11 80 ? ? ? ? C7 80 ? ? ? ? 09 00 00 00",
        "41 B0 01 8B D0 48 8B CE 8B D8 E8 * * * * 48 8B 15 ? ? ? ? 41 3B DD",
    ]},
}
NMSPY_HOOKS = {  # our name -> (nmspy class, method)
    "PLAYER_UPDATE": ("cGcPlayer", "Update"),
    "FSM_STATE_CHANGE": ("cTkFSM", "StateChange"),
    "FRONTEND_ACTIVATE": ("cGcFrontendManager", "Activate"),
}


def _nmspy_pattern(cls: str, fn: str) -> str | None:
    """The pattern string NMS.py hooks cls.fn with (what pyMHF caches by), or None."""
    try:
        import nmspy.data.types as nms
        sig = getattr(getattr(getattr(nms, cls), fn), "_signature", None)
        if isinstance(sig, str) and sig:
            return sig
    except Exception:
        pass
    try:  # from the source: the decorator line right above "def fn("
        import inspect
        import nmspy.data.types as nms
        src = inspect.getsource(getattr(nms, cls))
        m = re.search(r'function_hook\(\s*(?:signature=)?"([^"]+)"[^\n]*\)\s*\n\s*def ' + re.escape(fn) + r"\(", src)
        return m.group(1) if m else None
    except Exception:
        return None


def _nmspy_matches(img, pattern: str):
    """RVAs where NMS.py's pattern matches in .text (pyMHF takes the first; '??' and '?' are its wildcards)."""
    norm = " ".join("?" if t in ("?", "??") else t for t in pattern.split())
    return sorted(_addr_scan(img, norm, {}))


def guard() -> dict:
    status = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "hooks": {}}
    try:
        import pymhf.core._internal as _pi
        from pymhf.core import caching as _caching
        img = _AddrImage(base=_pi.BASE_ADDRESS, path=_pi.BINARY_PATH)
    except Exception:
        logger.exception("update guard: cannot read the game image; NMS.py's hooks are unchecked")
        status["error"] = "cannot read the game image"
        return status
    status["build"] = [f"0x{img.build[0]:X}", f"0x{img.build[1]:X}"]
    status["known_build"] = img.build == _ADDR_KNOWN_BUILD
    ours = _addr_resolve(ADDRESSES, logger, img)
    for name, (cls, fn) in NMSPY_HOOKS.items():
        entry = {"nmspy": f"{cls}::{fn}", "ours": f"NMS+0x{ours[name]:X}" if ours[name] else None}
        pattern = _nmspy_pattern(cls, fn)
        if not pattern:
            entry["action"] = "nmspy pattern not found: unchecked"
            logger.warning("update guard: no NMS.py pattern for %s::%s found: unchecked", cls, fn)
            status["hooks"][name] = entry
            continue
        try:
            matches = _nmspy_matches(img, pattern)
        except Exception as e:
            matches = []
            entry["scan_error"] = repr(e)
        entry["nmspy_matches"] = [f"NMS+0x{m:X}" for m in matches[:6]] + (["..."] if len(matches) > 6 else [])
        v = ours[name]
        if v and matches == [v]:
            entry["action"] = "ok"
            logger.info("update guard: %s::%s at NMS+0x%X, NMS.py's pattern agrees", cls, fn, v)
        elif v:
            try:
                _caching.offset_cache.set(pattern, v, None, False)
                entry["action"] = "primed pyMHF's offset cache"
                logger.warning("update guard: NMS.py's pattern for %s::%s %s; pyMHF told to use NMS+0x%X "
                               "(our patterns)", cls, fn,
                               "matches nothing" if not matches else
                               f"matches {len(matches)} places, first NMS+0x{matches[0]:X}", v)
            except Exception:
                entry["action"] = "priming failed"
                logger.exception("update guard: could not set pyMHF's offset cache for %s::%s", cls, fn)
        elif len(matches) == 1:
            entry["action"] = "trusting NMS.py (ours not found)"
            logger.warning("update guard: our patterns for %s::%s found nothing; NMS.py's one match NMS+0x%X "
                           "stands unverified", cls, fn, matches[0])
        else:
            entry["action"] = "BROKEN: neither found it"
            logger.error("update guard: %s::%s: our patterns found nothing and NMS.py's pattern matches %d places: "
                         "hooks on it will not work until the patterns are refreshed", cls, fn, len(matches))
        status["hooks"][name] = entry
    try:
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=1)
    except OSError:
        pass
    return status


STATUS = guard()

try:
    from pymhf import Mod
    from pymhf.gui.decorators import no_gui

    @no_gui
    class UpdateGuard(Mod):
        __author__ = "Traveller"
        __description__ = "Checks NMS.py's hook patterns against our own after a game update"
        __version__ = "0.1"
except Exception:  # (outside pyMHF, e.g. tools/check_addresses.py reading this file: nothing to define)
    pass
