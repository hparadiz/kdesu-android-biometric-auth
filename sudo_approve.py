#!/usr/bin/env python3
"""Optional: approve `sudo` from a local Kitty/Konsole terminal on the enrolled phone.

Installed only when built with sudo approval (`make install ENABLE_SUDO=yes`, Gentoo USE=sudo),
and active only after an administrator adds this to /etc/pam.d/sudo, before system-auth:

    auth  sufficient  pam_exec.so quiet stdout seteuid /usr/libexec/navi-auth/sudo-approve

pam_exec runs this inside sudo; `seteuid` makes it run as root (without it, pam_exec uses the
invoking user's real UID and this helper always falls back to the password). Exit 0 approves; any other exit lets PAM continue to the
normal password prompt. Phone approval is offered only when every check below passes; the
terminal check decides *where* the phone is offered, it is not a security boundary against code
already running as the user. The fingerprint approval on the phone is the gate.
"""
import argparse
import asyncio
import fcntl
import importlib.util
import os
import pwd
import re
import shlex
import signal
import sys
import time
from pathlib import Path

SSHD_NAMES = {"sshd", "sshd-session", "sshd-auth"}
TERMINAL_NAMES = {"konsole": "Konsole", "kitty": "Kitty"}
MAX_DEPTH = 64


class Skip(Exception):
    """Phone approval is not offered here; fall back to the password (no error shown)."""


def say(text):
    # pam_exec's "stdout" option shows each line in the terminal as PAM text.
    print(text, flush=True)


def proc_exe(pid, root="/proc"):
    try:
        target = os.readlink(f"{root}/{pid}/exe")
    except OSError:
        return ""
    return target[:-len(" (deleted)")] if target.endswith(" (deleted)") else target  # upgraded while running


def proc_parent_and_uid(pid, root="/proc"):
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


def find_terminal(sudo_pid, uid, terminals, root="/proc"):
    """The allowed terminal emulator above sudo, owned by the user; no sshd anywhere in the chain."""
    found = None
    pid = sudo_pid
    for _ in range(MAX_DEPTH):
        ppid, _, _ = proc_parent_and_uid(pid, root)
        if ppid <= 1:
            break
        pid = ppid
        _, owner, comm = proc_parent_and_uid(pid, root)
        exe = proc_exe(pid, root)
        if comm in SSHD_NAMES or os.path.basename(exe) in SSHD_NAMES:
            raise Skip("sudo runs inside an SSH session")
        if found is None and exe in terminals and owner == uid:
            found = exe
    if found is None:
        raise Skip("sudo is not running in an allowed local terminal")
    return found


def sudo_command(argv):
    """Display text and target user from sudo's own argv (a hint: sudo decides what actually runs)."""
    target = "root"
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        if arg in ("-u", "--user") and index + 1 < len(argv):
            target = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--user="):
            target = arg.split("=", 1)[1]
        elif arg.startswith("-u") and len(arg) > 2:
            target = arg[2:]
        elif arg in ("-g", "--group", "-C", "--close-from", "-D", "--chdir", "-h", "--host", "-p", "--prompt",
                     "-R", "--chroot", "-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user"):
            index += 1  # option with a separate value
        index += 1
    text = "sudo " + shlex.join(argv[1:])
    text = "".join(c if c.isprintable() else "?" for c in text)
    for low, high in ((0x202a, 0x202e), (0x2066, 0x2069)):
        text = "".join("?" if low <= ord(c) <= high else c for c in text)
    if len(text) > 512:
        text = text[:509] + "..."
    if not re.fullmatch(r"#?[A-Za-z0-9_.@-]{1,64}", target):
        target = "?"
    return text, target


def desktop_environment(sudo_pid, root="/proc"):
    try:
        with open(f"{root}/{sudo_pid}/environ", "rb") as environ:
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


def load_rootauth():
    spec = importlib.util.spec_from_file_location("navi_rootauth", Path(__file__).resolve().with_name("rootauth.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_pam(environ):
    if os.geteuid() != 0:
        raise Skip("not running as root (add 'seteuid' to the pam_exec line in /etc/pam.d/sudo)")
    if environ.get("PAM_SERVICE") != "sudo" or environ.get("PAM_TYPE") != "auth":
        raise Skip("only sudo authentication is supported")
    if environ.get("PAM_RHOST"):
        raise Skip("remote host")
    if not re.fullmatch(r"/dev/pts/[0-9]{1,6}", environ.get("PAM_TTY", "")):
        raise Skip("no terminal")
    user = environ.get("PAM_USER", "")
    try:
        return pwd.getpwnam(user)
    except KeyError:
        raise Skip("unknown user") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal", action="append", default=[], help="Allowed terminal executable (repeatable)")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    terminals = set(args.terminal) or {"/usr/bin/konsole", "/usr/bin/kitty"}
    timeout = max(10, min(args.timeout, 115))  # the phone request lifetime is at most 120 s
    rootauth = None
    try:
        account = check_pam(os.environ)
        sudo_pid = os.getppid()
        if os.path.basename(proc_exe(sudo_pid)) != "sudo":
            raise Skip("not started by sudo")
        terminal = find_terminal(sudo_pid, account.pw_uid, terminals)
        with open(f"/proc/{sudo_pid}/cmdline", "rb") as cmdline:
            sudo_argv = [part.decode(errors="replace") for part in cmdline.read(65536).split(b"\0") if part]
        command, target = sudo_command(sudo_argv)
        rootauth = load_rootauth()
        rootauth.check_implementation()
        rootauth.private_directory(rootauth.STATE, 0o700)
        try:
            environment = rootauth.validate_environment(desktop_environment(sudo_pid), account.pw_uid)
        except Exception:
            environment = {}  # KDE Connect needs the session bus; LAN and ntfy routes do not.
        name = TERMINAL_NAMES.get(os.path.basename(terminal), os.path.basename(terminal))
        with (rootauth.STATE / "authority.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Skip("another Navi request is in progress") from None
            authority = rootauth.Authority()
            if authority.account.pw_uid != account.pw_uid:
                raise Skip("this account is not enrolled for phone approval")
            context = {"application": f"sudo · {name}", "action_id": "sudo", "command": command,
                       "command_hidden": False, "requesting_user": account.pw_name, "requesting_uid": account.pw_uid,
                       "target_user": target, "source": "sudo", "mode": "approve", "icon_name": "utilities-terminal",
                       "icon_png_base64": "", "tty": os.environ["PAM_TTY"]}
            rootauth.audit(f"sudo-start user={account.pw_name} terminal={name} tty={os.environ['PAM_TTY']}")
            say(f"Approve this sudo in Navi on your phone… (Ctrl-C to cancel; password after {timeout} s)")
            try:
                asyncio.run(_approve(authority, context, environment, timeout, name))
            finally:
                authority.db.close()
        return 0
    except Skip as reason:
        if rootauth is None:
            try:
                rootauth = load_rootauth()
            except Exception:
                pass
        if rootauth is not None:
            rootauth.audit(f"sudo-skipped: {reason}")
        return 1
    except (Exception, KeyboardInterrupt, asyncio.CancelledError) as error:
        if rootauth is not None:
            rootauth.audit(f"sudo-not-approved: {type(error).__name__}: {error}"[:300])
        say("Not approved on the phone — use your password.")
        return 1


async def _approve(authority, context, environment, timeout, name):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    await authority.approve_only(context, environment, time.monotonic() + timeout,
                                 f"Approve sudo in {name}", "sudo")


if __name__ == "__main__":
    sys.exit(main())
