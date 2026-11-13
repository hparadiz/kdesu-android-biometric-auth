#!/usr/bin/env python3
"""One-dialog phone verifier/executor, connected to kdesu by inherited pipes."""
import asyncio
import base64
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import time
import uuid

# Load only the adjacent installed, root-owned implementation, never PYTHONPATH.
_spec = importlib.util.spec_from_file_location("phone_crypto", Path(__file__).with_name("host.py"))
crypto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crypto)

PROTOCOL = "navi-auth-exec/v1"
STATE = Path("/var/lib/navi-auth")
RUNTIME = Path("/run/navi-auth")
CONFIG = Path("/etc/navi-auth/config.json")
MAX_MESSAGE = 65536


def audit(message):
    # Closing or filling the caller's diagnostic pipe cannot interrupt authority.
    try:
        os.set_blocking(2, False)
        data = (time.strftime("%Y-%m-%dT%H:%M:%S%z") + " " + message + "\n").encode("utf-8", errors="replace")
        os.write(2, data[:2048])
    except OSError:
        pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON field")
        value[key] = item
    return value


def trusted_file(path, private=False):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
        raise ValueError(f"Unsafe ownership or permissions: {path}")
    if info.st_size > MAX_MESSAGE:
        raise ValueError(f"Oversized configuration: {path}")
    return path.read_bytes()


def private_directory(path, mode):
    if not path.exists():
        path.mkdir(mode=mode)
        path.chmod(mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError(f"Expected root-owned directory with mode {mode:o}: {path}")


def plain(value, limit, field, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not value and not empty) or any(
            ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or 0x202a <= ord(c) <= 0x202e
            or 0x2066 <= ord(c) <= 0x2069 or 0xd800 <= ord(c) <= 0xdfff for c in value):
        raise ValueError(f"Invalid {field}")
    return value


def validate_start(event, peer_uid, account):
    if set(event) != {"protocol", "event", "request_id", "context", "environment", "cwd"}:
        raise ValueError("Unexpected execution request fields")
    if event["event"] != "start":
        raise ValueError("Expected execution start")
    supplied = event["context"]
    if not isinstance(supplied, dict):
        raise ValueError("Invalid request context")
    allowed = {"application", "action_id", "command", "command_hidden", "requesting_user", "requesting_uid",
               "target_user", "source", "requester_pid", "requester_executable", "icon_name", "icon_png_base64"}
    if set(supplied) - allowed:
        raise ValueError("Unexpected execution context")
    if supplied.get("command_hidden") is not False:
        raise ValueError("Phone execution requires a visible command")
    if supplied.get("source") != "kdesu" or supplied.get("action_id") != "org.kde.kdesu.run":
        raise ValueError("Only real KDE execution requests are supported")
    if supplied.get("target_user") != "root":
        raise ValueError("This installation authorizes the root account only")
    if type(supplied.get("requesting_uid")) is not int or supplied["requesting_uid"] != peer_uid:
        raise ValueError("Requesting UID does not match the invoking account")
    if supplied.get("requesting_user") != account.pw_name:
        raise ValueError("Requesting account does not match the invoking account")
    context = {name: plain(supplied.get(name, ""), limit, name, empty)
               for name, limit, empty in (("application", 80, False), ("command", 512, False),
                   ("icon_name", 128, True), ("requester_executable", 4096, True))}
    encoded = supplied.get("icon_png_base64", "")
    if not isinstance(encoded, str) or len(encoded) > 21848:
        raise ValueError("Requester icon is too large")
    if encoded:
        icon = base64.b64decode(encoded, validate=True)
        if not 33 <= len(icon) <= 16384 or icon[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR":
            raise ValueError("Invalid requester PNG")
        if any(not 1 <= n <= 256 for n in struct.unpack(">II", icon[16:24])):
            raise ValueError("Invalid requester icon dimensions")
    requester_pid = supplied.get("requester_pid")
    if type(requester_pid) is not int or not 0 < requester_pid <= 2147483647:
        raise ValueError("Invalid requester PID")
    context.update(action_id="org.kde.kdesu.run", command_hidden=False, requesting_user=account.pw_name,
                   requesting_uid=peer_uid, target_user="root", source="kdesu", requester_pid=requester_pid,
                   icon_png_base64=encoded, mode="execute", desktop_request_id=event["request_id"])
    environment = event["environment"]
    if not isinstance(environment, dict) or set(environment) - {
            "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XAUTHORITY"}:
        raise ValueError("Unsupported execution environment")
    runtime = f"/run/user/{peer_uid}"
    for name, value in environment.items():
        plain(value, 512, name)
    if environment.get("XDG_RUNTIME_DIR", runtime) != runtime:
        raise ValueError("Desktop runtime directory does not match the invoking account")
    if "WAYLAND_DISPLAY" in environment and not re.fullmatch(r"wayland-[0-9]+", environment["WAYLAND_DISPLAY"]):
        raise ValueError("Invalid Wayland display")
    if "DISPLAY" in environment and not re.fullmatch(r":[0-9]+(?:\.[0-9]+)?", environment["DISPLAY"]):
        raise ValueError("Only a local X display is supported")
    if "DBUS_SESSION_BUS_ADDRESS" in environment:
        address = re.fullmatch(r"unix:path=(/[A-Za-z0-9_./-]+)(?:,guid=[0-9a-f]{32})?", environment["DBUS_SESSION_BUS_ADDRESS"])
        if not address:
            raise ValueError("Only a local Unix session bus is supported")
        info = Path(address[1]).lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != peer_uid:
            raise ValueError("Session bus is not owned by the desktop account")
    if "XAUTHORITY" in environment:
        path = Path(environment["XAUTHORITY"])
        if path.parent != Path(runtime):
            raise ValueError("X authority must be in the desktop runtime directory")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != peer_uid or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError("Unsafe X authority file")
    if "WAYLAND_DISPLAY" in environment or "DBUS_SESSION_BUS_ADDRESS" in environment:
        info = Path(runtime).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != peer_uid or info.st_mode & 0o022:
            raise ValueError("Unsafe desktop runtime directory")
    # Environment that can change executable/library/config lookup is never inherited.
    execution_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "USER": "root", "LOGNAME": "root",
                     "LANG": "C.UTF-8", "KDESU_USER": account.pw_name}
    execution_env.update(environment)
    cwd = plain(event["cwd"], 4096, "working directory")
    if not cwd.startswith("/") or not Path(cwd).is_dir():
        raise ValueError("Working directory must be an existing absolute directory")
    return context, execution_env, cwd


async def read_event(reader, deadline):
    raw = await asyncio.wait_for(reader.readline(), max(0.01, deadline - time.monotonic()))
    if not raw:
        raise ConnectionError("Desktop disconnected")
    if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
        raise ValueError("Oversized desktop message")
    event = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(event, dict) or event.get("protocol") != PROTOCOL:
        raise ValueError("Unknown execution protocol")
    request_id = event.get("request_id")
    if not isinstance(request_id, str) or str(uuid.UUID(request_id)) != request_id:
        raise ValueError("Invalid desktop request UUID")
    return event


async def send(writer, event, request_id, **values):
    writer.write(crypto.encode(dict(protocol=PROTOCOL, event=event, request_id=request_id, **values)) + b"\n")
    await asyncio.wait_for(writer.drain(), 2)


@contextmanager
def commit_guard():
    fd = os.open(STATE / "commit.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("Unsafe commit lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def revoke_for_device(uid, event):
    if set(event) != {"protocol", "event", "request_id", "kdeconnect_device"} or event["event"] != "revoke":
        raise ValueError("Invalid revocation request")
    with commit_guard():
        config = json.loads(trusted_file(CONFIG, True), object_pairs_hook=unique_object)
        if uid == 0 or config.get("uid") != uid:
            raise ValueError("Revocation does not match the invoking account and device")
        entries = phone_entries(config)
        matching = [entry for entry in entries if entry.get("kdeconnect_device") == event["kdeconnect_device"]]
        if not matching:
            raise ValueError("Revocation does not match an enrolled device")
        for entry in matching:
            entry["enabled"] = False
        config = dict(enabled=any(entry.get("enabled", True) for entry in entries), uid=config["uid"],
                      machine_key_id=config["machine_key_id"], phones=entries)
        crypto.atomic_write(CONFIG, crypto.encode(config))
        audit("phone-authority-revoked uid=" + str(uid))


def authority_status(uid, event):
    """Read-only summary for the invoking account; never exposes logs, executions or certificates."""
    if set(event) != {"protocol", "event", "request_id"} or event["event"] != "status":
        raise ValueError("Invalid status request")
    if not CONFIG.exists():
        return dict(configured=False)
    try:
        config = json.loads(trusted_file(CONFIG, True), object_pairs_hook=unique_object)
        entries = phone_entries(config)
    except Exception as error:
        return dict(configured=True, valid=False, reason=str(error)[:200])
    matches = uid != 0 and config.get("uid") == uid
    phones = []
    if matches:
        for entry in entries:
            expires = None
            try:
                leaf = crypto.x509.load_der_x509_certificate(base64.b64decode(entry["phone_certificate_b64"], validate=True))
                expires = leaf.not_valid_after_utc.isoformat()
            except Exception:
                pass
            phones.append(dict(phone_key_id=entry["phone_key_id"], enabled=entry.get("enabled", True),
                               transport=entry.get("transport"), kdeconnect_device=entry.get("kdeconnect_device"),
                               certificate_expires=expires))
    return dict(configured=True, valid=True, account_matches=matches,
                enabled=bool(config.get("enabled", True)) if matches else None,
                machine_key_id=config.get("machine_key_id") if matches else None, phones=phones)


def phone_entries(config):
    entries = config.get("phones")
    if entries is None:
        entries = [{name: config[name] for name in (
            "enabled", "phone_key_id", "phone_certificate_b64", "transport", "endpoint", "kdeconnect_device")
            if name in config}]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ValueError("Expected between one and 32 enrolled phones")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("phone_key_id"), str) or not re.fullmatch(r"[a-f0-9]{64}", entry["phone_key_id"]):
            raise ValueError("Invalid enrolled phone entry")
        if entry["phone_key_id"] in seen:
            raise ValueError("Duplicate enrolled phone")
        seen.add(entry["phone_key_id"])
        if type(entry.get("enabled", True)) is not bool:
            raise ValueError("Invalid phone enablement")
    return entries


class PhoneAttempt:
    """One phone's independently signed challenge and bounded transport work."""
    def __init__(self, authority, config):
        self.authority = authority
        self.config = config
        self.leaf = crypto.x509.load_der_x509_certificate(crypto.unb64(config["phone_certificate_b64"]))
        crypto.validate_certificate(self.leaf, authority.root)
        self.phone_key_id = crypto.digest(crypto.spki(self.leaf.public_key()))
        if config["phone_key_id"] != self.phone_key_id:
            raise ValueError("Phone certificate does not match its configured key")
        self.kdeconnect_device = config.get("kdeconnect_device")
        transport = config.get("transport", "lan")
        if transport not in {"lan", "kdeconnect-share"}:
            raise ValueError("Unknown phone transport")
        self.kde_messages = transport == "kdeconnect-share"
        if self.kde_messages or self.kdeconnect_device is not None:
            if not isinstance(self.kdeconnect_device, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.kdeconnect_device):
                raise ValueError("The paired KDE Connect device is required")
        if not self.kde_messages and not self.kdeconnect_device:
            plain(config.get("endpoint"), 128, "Phone LAN endpoint")
        if not self.kde_messages and config.get("endpoint") is not None:
            crypto.NetworkPhone(plain(config["endpoint"], 128, "Phone LAN endpoint"),
                                authority.key, authority.root, self.leaf)
        self.phone = None
        self.request_id = None
        self.payload = None
        self.request = None
        self.delivery_started = False
        self.delivered = False
        self.error = None
        self.stopping = asyncio.Event()
        self.task = None
        self.cleanup = None

    def connect(self, environment):
        owner = self.authority
        if self.kde_messages:
            return crypto.kdeconnect_transport()(crypto, self.kdeconnect_device,
                owner.key, owner.root, self.leaf, owner.account, environment)
        resolver = None
        if self.kdeconnect_device:
            resolver = lambda **options: crypto.kdeconnect_endpoint(
                self.kdeconnect_device, environment, owner.account, **options)
        return crypto.NetworkPhone(self.config.get("endpoint"), owner.key, owner.root, self.leaf, resolver)

    async def deliver(self, filename, value, canceled=False):
        await asyncio.to_thread(self.phone.write, filename, value)
        if filename != "receipt.json":
            await asyncio.to_thread(self.phone.notify, self.request_id, canceled)

    async def run(self, desktop_id, context, execution, environment, deadline):
        owner = self.authority
        try:
            audit(f"phone-attempt desktop={desktop_id} phone={self.phone_key_id}")
            self.phone = await asyncio.to_thread(self.connect, environment)
            if self.stopping.is_set() or time.monotonic() >= deadline:
                return None
            self.request_id = secrets.token_hex(16)
            now = int(time.time() * 1000)
            leaf_der = self.leaf.public_bytes(crypto.serialization.Encoding.DER)
            self.payload = dict(domain=crypto.DOMAIN, kind="authenticate", request_id=self.request_id,
                nonce=crypto.b64(secrets.token_bytes(32)), machine_id=owner.machine_id, phone_key_id=self.phone_key_id,
                certificate_sha256=crypto.digest(leaf_der), machine_name=socket.gethostname(),
                operation="Run this command as root", issued_at_ms=now,
                expires_at_ms=now + int((deadline - time.monotonic()) * 1000),
                context=context, execution=execution)
            if self.kde_messages:
                self.payload["transport"] = self.phone.transport
            self.request = crypto.envelope(owner.key, self.payload)
            self.request.update(machine_certificate_b64=crypto.b64(owner.root.public_bytes(crypto.serialization.Encoding.DER)),
                                phone_certificate_b64=crypto.b64(leaf_der))
            with owner.db:
                owner.db.execute("INSERT INTO requests VALUES(?,?,?,'pending')",
                                 (self.request_id, desktop_id, crypto.encode(self.payload)))
            self.delivery_started = True
            await self.deliver("request.json", self.request)
            self.delivered = True
            audit(f"requested request={self.request_id} desktop={desktop_id} phone={self.phone_key_id}")
            while not self.stopping.is_set() and time.monotonic() < deadline:
                value = await asyncio.to_thread(self.phone.read, "response.json")
                if self.stopping.is_set():
                    return None
                if value and value.get("request_id") == self.request_id:
                    if value.get("status") != "signed":
                        raise ValueError("Phone approval was declined")
                    if crypto.unb64(value["payload_b64"]) != crypto.encode(self.payload) or value["phone_certificate_b64"] != self.request["phone_certificate_b64"]:
                        raise ValueError("Phone response does not match this exact execution")
                    signature = crypto.unb64(value["signature_b64"])
                    self.leaf.public_key().verify(signature, crypto.encode(self.payload), crypto.ec.ECDSA(crypto.hashes.SHA256()))
                    crypto.validate_certificate(self.leaf, owner.root)
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Approval expired")
                    return signature
                try:
                    await asyncio.wait_for(self.stopping.wait(), 0.5)
                except TimeoutError:
                    pass
            return None
        except Exception as error:
            self.error = type(error).__name__ + ": " + str(error)[:180]
            audit(f"phone-unavailable desktop={desktop_id} phone={self.phone_key_id}: {self.error}")
            raise

    def withdraw(self):
        self.stopping.set()
        if self.cleanup is None:
            self.cleanup = asyncio.create_task(self.finish(False))
        return self.cleanup

    async def finish(self, committed):
        # Do not cancel to_thread wrappers: their actual I/O must finish before
        # a signed withdrawal, including a request whose delivery returned late.
        self.stopping.set()
        if self.task is not None:
            await asyncio.gather(self.task, return_exceptions=True)
        if self.request_id and not committed:
            with self.authority.db:
                self.authority.db.execute("UPDATE requests SET status='canceled' WHERE id=? AND status IN ('pending','ready')", (self.request_id,))
            if self.delivery_started:
                try:
                    cancel = crypto.envelope(self.authority.key, dict(domain=crypto.DOMAIN, kind="cancel", request_id=self.request_id,
                        machine_id=self.authority.machine_id, phone_key_id=self.phone_key_id,
                        request_sha256=crypto.digest(crypto.encode(self.payload))))
                    await self.deliver("cancel.json", cancel, True)
                except Exception as error:
                    audit(f"phone-cancel-delivery-failed request={self.request_id}: {type(error).__name__}")
        if self.kde_messages and self.phone is not None:
            await asyncio.to_thread(self.phone.close)


class Authority:
    def __init__(self):
        config_bytes = trusted_file(CONFIG, True)
        self.config_digest = crypto.digest(config_bytes)
        config = json.loads(config_bytes, object_pairs_hook=unique_object)
        self.account = pwd.getpwuid(config["uid"])
        if config.get("enabled") is not True:
            raise ValueError("Phone authority is revoked or disabled")
        if self.account.pw_uid == 0:
            raise ValueError("A non-root desktop account is required")
        self.key = crypto.serialization.load_pem_private_key(trusted_file(STATE / "machine-key.pem", True), password=None)
        self.root = crypto.x509.load_pem_x509_certificate(trusted_file(STATE / "machine-cert.pem", True))
        crypto.validate_certificate(self.root, self.root, ca=True)
        if crypto.spki(self.key.public_key()) != crypto.spki(self.root.public_key()):
            raise ValueError("Machine identity mismatch")
        self.machine_id = crypto.digest(crypto.spki(self.root.public_key()))
        if config.get("machine_key_id") != self.machine_id:
            raise ValueError("Configured machine identity mismatch")
        self.attempts = [PhoneAttempt(self, entry) for entry in phone_entries(config) if entry.get("enabled", True)]
        if not self.attempts:
            raise ValueError("No enabled authenticator phones")
        self.db = sqlite3.connect(STATE / "executions.sqlite3")
        self.db.execute("CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, desktop_id TEXT NOT NULL, payload BLOB NOT NULL, status TEXT NOT NULL)")
        # The protected cross-process lock permits clearing only abandoned rows.
        self.db.execute("UPDATE requests SET status='canceled' WHERE status IN ('pending','ready')")
        self.db.commit()

    async def handle(self, reader, writer, uid, first_event=None):
        desktop_id = None
        winner = None
        committed = False
        watcher = None
        cwd_fd = None
        terminal_sent = False
        try:
            if uid != self.account.pw_uid:
                raise ValueError("Desktop account is not enrolled")
            event = first_event if first_event is not None else await read_event(reader, time.monotonic() + 5)
            desktop_id = event["request_id"]
            context, environment, cwd = validate_start(event, uid, self.account)
            deadline = time.monotonic() + 120
            watcher = asyncio.create_task(read_event(reader, deadline))
            cwd_fd = os.open(cwd, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            cwd = os.readlink(f"/proc/self/fd/{cwd_fd}")
            cwd_info = os.fstat(cwd_fd)
            execution = {"argv": ["/bin/sh", "-c", context["command"]], "uid": 0, "gid": 0,
                         "cwd": cwd, "cwd_device": cwd_info.st_dev, "cwd_inode": cwd_info.st_ino, "environment": environment}
            pending = {}
            for attempt in self.attempts:
                attempt.task = asyncio.create_task(attempt.run(desktop_id, context, execution, event["environment"], deadline))
                pending[attempt.task] = attempt
            while pending and winner is None:
                done, _ = await asyncio.wait({watcher, *pending}, return_when=asyncio.FIRST_COMPLETED)
                # Withdrawal wins a simultaneous race against any number of approvals.
                if watcher in done or reader.at_eof() or writer.is_closing():
                    if watcher.done():
                        message = watcher.result()
                        if message.get("event") == "cancel" and message["request_id"] == desktop_id:
                            await send(writer, "canceled", desktop_id)
                            terminal_sent = True
                    raise ConnectionError("Desktop withdrew before approval")
                for task in done:
                    attempt = pending.pop(task)
                    try:
                        signature = task.result()
                    except Exception:
                        attempt.withdraw()
                        continue
                    if signature is not None:
                        winner = attempt
                        break
            if winner is None:
                raise ConnectionError("No enrolled phone approved; devices may be offline or have declined")
            request_id, request, payload = winner.request_id, winner.request, winner.payload
            # Only this winner can become ready. Other phone proofs are withdrawn
            # concurrently; a slow/offline device cannot delay the command.
            for attempt in self.attempts:
                if attempt is not winner:
                    attempt.withdraw()
            with self.db:
                changed = self.db.execute("UPDATE requests SET status='ready' WHERE id=? AND status='pending'", (request_id,)).rowcount
                if changed != 1:
                    raise ValueError("Phone request is no longer pending")
            await send(writer, "ready", desktop_id)
            commit = await watcher
            if commit.get("event") == "cancel" and commit["request_id"] == desktop_id:
                await send(writer, "canceled", desktop_id)
                terminal_sent = True
                raise ConnectionError("Desktop withdrew before execution")
            if set(commit) != {"protocol", "event", "request_id"} or commit["event"] != "commit" or commit["request_id"] != desktop_id:
                raise ValueError("Expected commit for the approved desktop request")
            if time.monotonic() >= deadline or reader.at_eof() or writer.is_closing():
                raise TimeoutError("Execution expired or desktop disconnected")
            with commit_guard():
                if crypto.digest(trusted_file(CONFIG, True)) != self.config_digest:
                    raise ValueError("Phone approval was revoked or configuration changed")
                # No await between commit, consuming the single winner and launch.
                with self.db:
                    changed = self.db.execute("UPDATE requests SET status='consumed' WHERE id=? AND status='ready'", (request_id,)).rowcount
                    if changed != 1:
                        raise ValueError("Execution approval was already consumed")
                committed = True
                log_fd = os.open(STATE / "commands.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    info = os.fstat(log_fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                        raise ValueError("Unsafe command log")
                    child = subprocess.Popen(["/bin/sh", "-c", context["command"]],
                        cwd=f"/proc/self/fd/{cwd_fd}", pass_fds=(cwd_fd,), env=environment,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=log_fd, start_new_session=True, umask=0o022, user=0, group=0, extra_groups=[])
                finally:
                    os.close(log_fd)
            audit(f"executed request={request_id} desktop={desktop_id} phone={winner.phone_key_id} uid=0 pid={child.pid}")
            receipt = crypto.envelope(self.key, dict(domain=crypto.DOMAIN, kind="receipt", request_id=request_id,
                machine_id=self.machine_id, phone_key_id=winner.phone_key_id, response_sha256=crypto.digest(signature),
                status="approved", verified_at_ms=int(time.time() * 1000), execution_pid=child.pid))
            crypto.atomic_write(STATE / "last-execution.json", crypto.encode(dict(request=request,
                signature_b64=crypto.b64(signature), receipt=receipt, pid=child.pid,
                phone_attempts=[dict(phone_key_id=a.phone_key_id, request_id=a.request_id,
                                     delivered=a.delivered, error=a.error) for a in self.attempts])))
            try:
                await winner.deliver("receipt.json", receipt)
            finally:
                await send(writer, "executed", desktop_id, pid=child.pid)
                terminal_sent = True
        except (Exception, asyncio.CancelledError) as error:
            audit(f"request-ended desktop={desktop_id} committed={committed} reason={type(error).__name__}: {error}")
            if desktop_id and not terminal_sent and not writer.is_closing():
                try:
                    await send(writer, "error", desktop_id, message="Execution status uncertain; do not retry automatically" if committed else str(error)[:180])
                except (Exception, asyncio.CancelledError):
                    pass
        finally:
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            cleanup = []
            for attempt in self.attempts:
                if attempt is winner and committed:
                    cleanup.append(attempt.finish(True))
                else:
                    cleanup.append(attempt.withdraw())
            # The KDE client detaches a committed helper; EOF does not stop its
            # bounded loser cleanup. Signed tombstones also handle reordered files.
            await asyncio.gather(*cleanup, return_exceptions=True)
            if cwd_fd is not None:
                os.close(cwd_fd)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


class PipeWriter:
    """Bounded nonblocking protocol output; stdout is never used for diagnostics."""
    def __init__(self, stream):
        self.stream = stream
        self.fd = stream.fileno()
        os.set_blocking(self.fd, False)
        self.pending = bytearray()
        self.closing = False

    def write(self, data):
        if self.closing or len(self.pending) + len(data) > 16384:
            raise ConnectionError("Desktop output unavailable")
        self.pending.extend(data)

    async def drain(self):
        loop = asyncio.get_running_loop()
        while self.pending:
            try:
                written = os.write(self.fd, self.pending)
                del self.pending[:written]
            except BlockingIOError:
                ready = loop.create_future()
                def writable():
                    if not ready.done():
                        ready.set_result(None)
                loop.add_writer(self.fd, writable)
                try:
                    await ready
                finally:
                    loop.remove_writer(self.fd)
            except OSError:
                self.closing = True
                raise

    def is_closing(self):
        return self.closing

    def close(self):
        self.closing = True
        self.stream.close()

    async def wait_closed(self):
        pass


async def run_stdio(uid):
    reader = asyncio.StreamReader(limit=MAX_MESSAGE)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    writer = PipeWriter(sys.stdout.buffer)
    authority = None
    try:
        event = await read_event(reader, time.monotonic() + 5)
        if event.get("event") == "revoke":
            revoke_for_device(uid, event)
            await send(writer, "revoked", event["request_id"])
            return
        if event.get("event") == "status":
            await send(writer, "status", event["request_id"], **authority_status(uid, event))
            return
        with (STATE / "authority.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            authority = Authority()
            if uid != authority.account.pw_uid:
                raise ValueError("Invoking account is not enrolled")
            task = asyncio.create_task(authority.handle(reader, writer, uid, event))
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                loop.add_signal_handler(sig, task.cancel)
            await task
    finally:
        transport.close()
        writer.close()
        if authority is not None:
            authority.db.close()


def main():
    if os.geteuid() != 0:
        raise ValueError("The installed authority must run as root")
    os.umask(0o077)
    for source in (Path(__file__).resolve(), Path(__file__).resolve().with_name("host.py"),
                   Path(__file__).resolve().with_name("kdeconnect_transport.py")):
        trusted_file(source)
        info = source.parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Authority implementation directory is not protected")
    private_directory(STATE, 0o700)
    private_directory(RUNTIME, 0o755)
    if sys.argv[1:] == ["--check"]:
        with (STATE / "authority.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            authority = Authority()
            print(f"Root identity and {len(authority.attempts)} phone approvals verified")
            authority.db.close()
    elif len(sys.argv) == 3 and sys.argv[1] == "--stdio" and sys.argv[2].isdecimal():
        for fd in (0, 1):
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                raise ValueError("Expected inherited process pipes")
        asyncio.run(run_stdio(int(sys.argv[2])))
    else:
        raise ValueError("Unexpected authority arguments")



if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        audit(f"authority-failed: {error}")
        raise SystemExit(1)
