#!/usr/bin/env python3
"""Optional: log in at SDDM or unlock the Plasma lock screen with the enrolled phone.

Installed only when built with login approval (USE=login / make install ENABLE_LOGIN=yes), and
active only after it is switched on in System Settings (or `navi-pam enable sddm|kde`), which adds

    auth  sufficient  pam_exec.so quiet stdout expose_authtok /usr/libexec/navi-auth/login-approve

above the password rules of /etc/pam.d/sddm and /etc/pam.d/kde. The password field arrives on
stdin: if anything was typed, this exits at once and the normal password check runs. With an empty
field (press Enter) the phone is asked. Exit 0 approves; anything else falls back to the password.

SDDM runs PAM as root, so this asks the root authority directly. The lock screen runs PAM as the
user, so it asks through the setuid helper, which builds the request itself. Console/getty login,
SSH, su, sudo and polkit prompts are never handled here.
"""
import asyncio
import fcntl
import json
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
import uuid
import importlib.util
from pathlib import Path

SDDM_HELPER = "/usr/libexec/sddm-helper"
SDDM = "/usr/bin/sddm"
LOCK_GREETER = "/usr/libexec/kscreenlocker_greet"
# Plasma 6.8+ authenticates in a separate worker started by the greeter.
LOCK_WORKER = "/usr/libexec/kscreenlocker_worker"
AUTHORIZE = Path("/usr/libexec/navi-auth/authorize")
EXEC_PROTOCOL = "navi-auth-exec/v1"
TIMEOUT = 60


def _common():
    spec = importlib.util.spec_from_file_location("navi_pam_common", Path(__file__).resolve().with_name("pam_common.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_pam = _common()
Skip, say = _pam.Skip, _pam.say


def check_sddm(environ, root="/proc", parent=None):
    """SDDM's root helper, started by sddm itself, for the configured service and a local seat."""
    if os.geteuid() != 0:
        raise Skip("SDDM approval must run as root")
    parent = os.getppid() if parent is None else parent
    if _pam.proc_exe(parent, root) != SDDM_HELPER or not _pam.root_owned_executable(f"{root}/{parent}/exe"):
        raise Skip("not started by sddm-helper")
    grandparent, parent_uid, _ = _pam.proc_parent_and_uid(parent, root)
    if parent_uid != 0 or _pam.proc_exe(grandparent, root) != SDDM:
        raise Skip("sddm-helper was not started by sddm")
    try:
        return pwd.getpwnam(environ.get("PAM_USER", ""))
    except KeyError:
        raise Skip("unknown user") from None


def check_lock_screen(environ, root="/proc", parent=None):
    """Pre-check for the user's own Plasma lock screen: kscreenlocker_worker started by kscreenlocker_greet
    (Plasma 6.8+), or kscreenlocker_greet itself (older Plasma).

    The lock screen marks itself non-dumpable, so its /proc/<pid>/exe is hidden even from its own user;
    only the (readable) process names and owners are checked here. The root authority repeats the check
    with full access to the kernel's records before it asks the phone, so this is not the gate.
    """
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise Skip("the lock screen never authenticates as root")
    parent = os.getppid() if parent is None else parent

    def is_ours(pid, path):
        _, owner, comm = _pam.proc_parent_and_uid(pid, root)
        if owner != uid or comm != os.path.basename(path)[:15]:  # comm is truncated to 15 characters
            return False
        exe = _pam.proc_exe(pid, root)
        return exe == path if exe else True  # Hidden exe: the authority verifies it as root.

    if is_ours(parent, LOCK_WORKER):
        grandparent = _pam.proc_parent_and_uid(parent, root)[0]
        if not is_ours(grandparent, LOCK_GREETER):
            raise Skip("the lock screen worker was not started by the user's lock screen")
    elif not is_ours(parent, LOCK_GREETER):
        raise Skip("not started by the Plasma lock screen")
    try:
        account = pwd.getpwnam(environ.get("PAM_USER", ""))
    except KeyError:
        raise Skip("unknown user") from None
    if account.pw_uid != uid:
        raise Skip("the lock screen belongs to another user")
    return account


def check_pam(environ):
    service = environ.get("PAM_SERVICE")
    if service not in ("sddm", "kde"):
        raise Skip("only the SDDM login and the Plasma lock screen are supported")
    if environ.get("PAM_TYPE") != "auth":
        raise Skip("only authentication is supported")
    if environ.get("PAM_RHOST"):
        raise Skip("remote host")
    return service


def approve_sddm(account):
    rootauth = _pam.load_rootauth()
    rootauth.check_implementation()
    rootauth.private_directory(rootauth.STATE, 0o700)
    with (rootauth.STATE / "authority.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Skip("another Navi request is in progress") from None
        authority = rootauth.Authority()
        try:
            if authority.account.pw_uid != account.pw_uid:
                raise Skip("this account is not enrolled for phone approval")
            context = {"application": "SDDM login", "action_id": "login", "command": "", "command_hidden": False,
                       "requesting_user": account.pw_name, "requesting_uid": account.pw_uid,
                       "target_user": account.pw_name, "source": "sddm", "mode": "approve",
                       "icon_name": "system-log-out", "icon_png_base64": ""}
            rootauth.audit(f"login-start user={account.pw_name}")

            async def run():
                loop = asyncio.get_running_loop()
                task = asyncio.current_task()
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    loop.add_signal_handler(sig, task.cancel)
                # No desktop session yet: KDE Connect is not running, so routing uses ntfy remote approvals.
                await authority.approve_only(context, {}, time.monotonic() + TIMEOUT,
                                             f"Log in {account.pw_name} on {socket.gethostname()}"[:160], "login")
            asyncio.run(run())
        finally:
            authority.db.close()


def approve_lock_screen(parent):
    """Ask the root authority through the setuid helper, which builds the unlock request itself."""
    info = AUTHORIZE.stat()
    if info.st_uid != 0 or not info.st_mode & 0o4000:
        raise Skip("the protected authority is not installed")
    request_id = str(uuid.uuid4())
    line = json.dumps({"protocol": EXEC_PROTOCOL, "event": "approve", "request_id": request_id, "kind": "unlock",
                       "environment": _pam.desktop_environment(parent)}) + "\n"
    try:
        # Pipes (not a pty or socket): the helper requires private FIFOs.
        result = subprocess.run([str(AUTHORIZE)], input=line.encode(), capture_output=True,
                                timeout=TIMEOUT + 15, env={}, cwd="/")
    except subprocess.TimeoutExpired:
        raise TimeoutError("The protected authority did not answer") from None
    for raw in result.stdout.splitlines():
        try:
            reply = json.loads(raw)
        except ValueError:
            continue
        if isinstance(reply, dict) and reply.get("request_id") == request_id:
            if reply.get("event") == "approved":
                return
            raise PermissionError(str(reply.get("message", "not approved")))
    raise PermissionError("no reply from the protected authority")


def main():
    log = None
    try:
        service = check_pam(os.environ)
        if _pam.typed_password():
            return 1  # A typed password goes straight to the normal check, with no delay.
        if service == "sddm":
            account = check_sddm(os.environ)
            say("Approve this login in Navi on your phone… (type your password instead to skip)")
            approve_sddm(account)
        else:
            check_lock_screen(os.environ)
            say("Approve the unlock in Navi on your phone… (type your password instead to skip)")
            approve_lock_screen(os.getppid())
        return 0
    except Skip as reason:
        log = f"{os.environ.get('PAM_SERVICE', '?')}-skipped: {reason}"
        return 1
    except (Exception, KeyboardInterrupt, asyncio.CancelledError) as error:
        log = f"{os.environ.get('PAM_SERVICE', '?')}-not-approved: {type(error).__name__}: {error}"[:300]
        say("Not approved on the phone — type your password.")
        return 1
    finally:
        if log:
            try:
                import syslog
                syslog.openlog("navi-auth", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
                syslog.syslog(syslog.LOG_INFO, log)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
