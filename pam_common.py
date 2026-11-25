#!/usr/bin/env python3
"""Shared helpers for Navi's optional PAM approval helpers (sudo, SDDM login, lock screen).

Installed only when built with one of them (USE=sudo / USE=login, make ENABLE_SUDO / ENABLE_LOGIN).
Nothing here grants anything: the helpers only decide whether to ask the phone, and the phone's
fingerprint signature, verified by the root authority, is the gate.
"""
import importlib.util
import os
import sys
from pathlib import Path

SSHD_NAMES = {"sshd", "sshd-session", "sshd-auth"}
MAX_DEPTH = 64
MAX_AUTHTOK = 4096


class Skip(Exception):
    """Phone approval is not offered here; fall back to the password (no error shown)."""


def say(text):
    # pam_exec's "stdout" option shows each line to the user as PAM information text.
    print(text, flush=True)


def proc_exe(pid, root="/proc"):
    try:
        target = os.readlink(f"{root}/{pid}/exe")
    except OSError:
        return ""
    return target[:-len(" (deleted)")] if target.endswith(" (deleted)") else target  # upgraded while running


def proc_parent_and_uid(pid, root="/proc"):
    """(parent pid, real uid, comm) from the kernel's records for pid."""
    with open(f"{root}/{pid}/stat", "rb") as stat_file:
        data = stat_file.read(4096).decode(errors="replace")
    ppid = int(data[data.rindex(")") + 2:].split()[1])
    uid = None
    with open(f"{root}/{pid}/status", "rb") as status_file:
        for line in status_file.read(16384).decode(errors="replace").splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])  # real uid
                break
    with open(f"{root}/{pid}/comm", "rb") as comm_file:
        comm = comm_file.read(64).decode(errors="replace").strip()
    return ppid, uid, comm


def root_owned_executable(path):
    """The binary a process runs must be root-owned and not writable by others."""
    try:
        info = os.stat(path)
    except OSError:
        return False
    return info.st_uid == 0 and not info.st_mode & 0o022


def desktop_environment(pid, root="/proc"):
    """DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR of a process (validated later by rootauth)."""
    try:
        with open(f"{root}/{pid}/environ", "rb") as environ:
            raw = environ.read(262144)
    except OSError:
        return {}
    wanted = {"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"}
    found = {}
    for item in raw.split(b"\0"):
        name, _, value = item.partition(b"=")
        name = name.decode(errors="replace")
        if name in wanted:
            found[name] = value.decode(errors="replace")
    return found


def typed_password(stream=None):
    """With pam_exec's expose_authtok the password field arrives on stdin. True when something was typed."""
    stream = stream if stream is not None else sys.stdin.buffer
    try:
        data = stream.read(MAX_AUTHTOK + 1)
    except (OSError, ValueError):
        return False
    return bool(data.split(b"\0", 1)[0].strip(b"\r\n"))


def load_rootauth():
    spec = importlib.util.spec_from_file_location("navi_rootauth", Path(__file__).resolve().with_name("rootauth.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.AUDIT_STDERR = False  # stderr is the user's terminal here; decisions go to journalctl -t navi-auth
    return module


def load_sibling(name):
    """Another installed helper module from this directory (isolated mode does not add it to sys.path)."""
    spec = importlib.util.spec_from_file_location(f"navi_{name}", Path(__file__).resolve().with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
