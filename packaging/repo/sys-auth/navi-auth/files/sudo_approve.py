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
import uuid
from pathlib import Path

TERMINAL_NAMES = {"konsole": "Konsole", "kitty": "Kitty"}


def _common():
    spec = importlib.util.spec_from_file_location("navi_pam_common", Path(__file__).resolve().with_name("pam_common.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_pam = _common()
Skip, say, proc_exe, proc_parent_and_uid = _pam.Skip, _pam.say, _pam.proc_exe, _pam.proc_parent_and_uid
desktop_environment, load_rootauth = _pam.desktop_environment, _pam.load_rootauth
SSHD_NAMES, MAX_DEPTH = _pam.SSHD_NAMES, _pam.MAX_DEPTH


def find_terminal(sudo_pid, uid, terminals, root="/proc", program=None):
    """The allowed terminal emulator above sudo, owned by the user; no sshd anywhere in the chain.

    If `program` is a list, the name of the program the terminal is running (for example an
    agent such as claude or codex, two levels below the terminal: terminal → shell → program) is
    appended when it is not sudo itself. It is a label for the phone, not a security check.
    """
    found = None
    pid = sudo_pid
    chain = []  # comm names from sudo's parent upwards
    for _ in range(MAX_DEPTH):
        ppid, _, _ = proc_parent_and_uid(pid, root)
        if ppid <= 1:
            break
        pid = ppid
        _, owner, comm = proc_parent_and_uid(pid, root)
        exe = proc_exe(pid, root)
        if comm in SSHD_NAMES or os.path.basename(exe) in SSHD_NAMES:
            raise Skip("sudo runs inside an SSH session")
        if found is None:
            if exe in terminals and owner == uid:
                found = exe
                if program is not None and len(chain) >= 2:
                    name = chain[-2]  # terminal → shell (chain[-1]) → program (chain[-2])
                    if re.fullmatch(r"[A-Za-z0-9_.+-]{1,32}", name) and name != "sudo":
                        program.append(name)
            else:
                chain.append(comm)
    if found is None:
        raise Skip("sudo is not running in an allowed local terminal")
    return found


def sudo_command(argv, limit=None):
    """Display text and target user from sudo's own argv (a hint: sudo decides what actually runs).

    The whole command is always shown: a command longer than the phone's display limit is not
    offered for phone approval at all (Skip), so nothing can be approved with a hidden tail.
    """
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
    # Newlines and tabs are kept (Navi lays them out); other invisible characters become "?".
    text = "".join(c if c.isprintable() or c in "\n\t" else "?" for c in text)
    for low, high in ((0x202a, 0x202e), (0x2066, 0x2069)):
        text = "".join("?" if low <= ord(c) <= high else c for c in text)
    if limit is not None and len(text) > limit:
        raise Skip(f"command too long to show on the phone ({len(text)} characters; limit {limit})")
    if not re.fullmatch(r"#?[A-Za-z0-9_.@-]{1,64}", target):
        target = "?"
    return text, target


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
        program = []
        terminal = find_terminal(sudo_pid, account.pw_uid, terminals, program=program)
        with open(f"/proc/{sudo_pid}/cmdline", "rb") as cmdline:
            sudo_argv = [part.decode(errors="replace") for part in cmdline.read(65536).split(b"\0") if part]
        rootauth = load_rootauth()
        try:
            command, target = sudo_command(sudo_argv, rootauth.crypto.MAX_COMMAND)
        except Skip:
            say(f"This command is too long to review on the phone (limit {rootauth.crypto.MAX_COMMAND} characters) — use your password, or split it up.")
            raise
        rootauth.check_implementation()
        rootauth.private_directory(rootauth.STATE, 0o700)
        try:
            environment = rootauth.validate_environment(desktop_environment(sudo_pid), account.pw_uid)
        except Exception:
            environment = {}  # KDE Connect needs the session bus; LAN and ntfy routes do not.
        name = TERMINAL_NAMES.get(os.path.basename(terminal), os.path.basename(terminal))
        # Which program asked (e.g. an agent running in the terminal), shown on the phone and logged.
        label = f"{name} · {program[0]}" if program else name
        tty = os.environ["PAM_TTY"]
        request = str(uuid.uuid4())
        with (rootauth.STATE / "authority.lock").open("a") as lock:
            # One phone request at a time: later ones (e.g. other agents) wait their turn.
            waited = False
            give_up = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= give_up:
                        say(f"Not approved on the phone (busy: another Navi request is still waiting) — request {request[:8]}.")
                        raise Skip(f"another Navi request is in progress; gave up after {timeout} s desktop={request}") from None
                    if not waited:
                        say(f"Waiting for another Navi request to finish… (request {request[:8]})")
                        waited = True
                    time.sleep(0.5)
            authority = rootauth.Authority()
            if authority.account.pw_uid != account.pw_uid:
                raise Skip("this account is not enrolled for phone approval")
            context = {"application": f"sudo · {label}"[:80], "action_id": "sudo", "command": command,
                       "command_hidden": False, "requesting_user": account.pw_name, "requesting_uid": account.pw_uid,
                       "target_user": target, "source": "sudo", "mode": "approve", "icon_name": "utilities-terminal",
                       "icon_png_base64": "", "tty": os.environ["PAM_TTY"]}
            rootauth.audit(f"sudo-start desktop={request} user={account.pw_name} terminal={name} "
                           f"program={program[0] if program else '-'} tty={tty}")
            say(f"Approve this sudo in Navi on your phone… (request {request[:8]}; Ctrl-C to cancel; password after {timeout} s)")
            try:
                asyncio.run(_approve(authority, context, environment, timeout, label, request))
            finally:
                authority.db.close()
            say(f"Approved on the phone — request {request[:8]}.")
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
        reason = "failed"
        if rootauth is not None:
            reason = {rootauth.Rejected: "rejected", rootauth.Unanswered: "timed out",
                      rootauth.Undelivered: "phone unreachable"}.get(type(error), reason)
        if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)):
            reason = "canceled"
        say(f"Not approved on the phone ({reason}) — use your password.")
        return 1


async def _approve(authority, context, environment, timeout, name, request):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    await authority.approve_only(context, environment, time.monotonic() + timeout,
                                 f"Approve sudo in {name}"[:160], "sudo", desktop_id=request)


if __name__ == "__main__":
    sys.exit(main())
