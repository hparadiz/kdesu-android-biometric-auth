#!/usr/bin/env python3
"""Signed-file transport through an already running, paired KDE Connect.

The child owns D-Bus and files as the desktop user. Nothing received from that
child is authorization: callers must verify the existing exact phone proof.
Importing this module does not connect to D-Bus or start a process.
"""

import base64
import collections
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit


MAX_FILE = 65536
MAX_FRAME = 131072
RPC_SECONDS = 10
RETENTION_SECONDS = 600
MAX_SPOOL_FILES = 96
DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
DEVICE_PATH_ID = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
REQUEST_ID = re.compile(r"[a-f0-9]{32}\Z")
MAIL_FILE = re.compile(r"navi-auth-(request|receipt|cancel)-[a-f0-9]{32}\.json\Z")
SERVICE = "org.kde.kdeconnect"
SHARE_INTERFACE = "org.kde.kdeconnect.device.share"


def _encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid_number(value):
        raise ValueError("Invalid JSON number")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_number)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _write_all(fd, data, deadline):
    while data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
            raise TimeoutError("KDE Connect transport write timed out")
        try:
            count = os.write(fd, data)
        except BlockingIOError:
            continue
        if count <= 0:
            raise ConnectionError("KDE Connect transport closed")
        data = data[count:]


class KdeConnectPhone:
    """NetworkPhone-compatible adapter; check() reports routing availability."""

    def __init__(self, crypto, device_id, machine_key, root, leaf, account=None, environment=None):
        if not isinstance(device_id, str) or not DEVICE_PATH_ID.fullmatch(device_id):
            raise ValueError("Invalid KDE Connect device ID")
        crypto.validate_certificate(leaf, root)
        self.crypto, self.key, self.root, self.leaf = crypto, machine_key, root, leaf
        self.phone_id = crypto.digest(crypto.spki(leaf.public_key()))
        self.request_id = None
        self._request = None
        self._input = bytearray()
        self._lock = threading.RLock()
        self._process = None
        desktop = account or pwd.getpwuid(os.getuid())
        if desktop.pw_uid == 0 or (os.geteuid() != 0 and desktop.pw_uid != os.getuid()):
            raise ValueError("KDE Connect requires the non-root desktop account")
        supplied = dict(os.environ if environment is None else environment)
        runtime = f"/run/user/{desktop.pw_uid}" if os.geteuid() == 0 else supplied.get("XDG_RUNTIME_DIR", f"/run/user/{desktop.pw_uid}")
        env = {"PATH": "/usr/bin:/bin", "HOME": desktop.pw_dir, "XDG_RUNTIME_DIR": runtime,
               "DBUS_SESSION_BUS_ADDRESS": supplied.get("DBUS_SESSION_BUS_ADDRESS", "")}
        if not env["DBUS_SESSION_BUS_ADDRESS"]:
            raise ValueError("The desktop session D-Bus address is required")
        options = {}
        if os.geteuid() == 0:
            options.update(user=desktop.pw_uid, group=desktop.pw_gid, extra_groups=[])
        try:
            self._process = subprocess.Popen(
                ["/usr/bin/python3.14", "-I", str(Path(__file__).resolve()), "--worker", device_id],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd="/", env=env, close_fds=True, start_new_session=True, umask=0o077, **options)
            os.set_blocking(self._process.stdin.fileno(), False)
            os.set_blocking(self._process.stdout.fileno(), False)
            hello = self._receive(time.monotonic() + RPC_SECONDS)
            desktop_id = hello.get("desktop_device_id")
            if hello.get("ok") is not True or not isinstance(desktop_id, str) or not DEVICE_ID.fullmatch(desktop_id):
                raise ValueError(hello.get("error", "KDE Connect transport did not initialize"))
            self.transport = {"kind": "kdeconnect-share", "desktop_device_id": desktop_id}
        except BaseException:
            self.close()
            raise

    def _receive(self, deadline):
        while True:
            if b"\n" in self._input:
                raw, _, remainder = self._input.partition(b"\n")
                self._input = bytearray(remainder)
                return _object(raw)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self._process.stdout], [], [], remaining)[0]:
                raise TimeoutError("KDE Connect transport response timed out")
            raw = os.read(self._process.stdout.fileno(), min(8192, MAX_FRAME + 1 - len(self._input)))
            if not raw:
                raise ConnectionError("KDE Connect transport exited")
            self._input.extend(raw)
            if len(self._input) > MAX_FRAME:
                raise ValueError("Oversized KDE Connect transport response")

    def _rpc(self, operation, **fields):
        with self._lock:
            if self._process is None:
                raise ConnectionError("KDE Connect transport is closed")
            raw = _encode({"operation": operation, **fields}) + b"\n"
            if len(raw) > MAX_FRAME:
                raise ValueError("Oversized KDE Connect transport command")
            try:
                deadline = time.monotonic() + RPC_SECONDS
                _write_all(self._process.stdin.fileno(), raw, deadline)
                reply = self._receive(deadline)
                if reply.get("ok") is not True:
                    raise ValueError(reply.get("error", "KDE Connect transport failed"))
                return reply.get("value")
            except BaseException:
                # A timed-out command cannot leave its reply for the next call.
                self.close()
                raise

    def check(self):
        self._rpc("check")
        return self.identity()

    def identity(self):
        return dict(key_id_sha256=self.phone_id,
                    public_key_spki_base64=self.crypto.b64(self.crypto.spki(self.leaf.public_key())))

    def write(self, name, value):
        if name not in {"request.json", "receipt.json", "cancel.json"}:
            raise ValueError("Invalid computer message name")
        # Keep our own copy: later terminal envelopes must carry the exact request.
        value = _object(self.crypto.encode(value))
        if name == "request.json":
            payload = _object(self.crypto.unb64(value["payload_b64"]))
            request_id = payload.get("request_id")
            if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
                raise ValueError("Invalid phone request ID")
            if payload.get("transport") != self.transport:
                raise ValueError("The signed request must bind the KDE Connect return device")
            if self.request_id is not None:
                raise ValueError("This KDE Connect transport already sent a request")
            self.request_id, self._request = request_id, value
        if self._request is None:
            raise ValueError("A terminal message requires its original signed request")
        mail = {"domain": self.crypto.DOMAIN, "kind": "kdeconnect-mail", "name": name,
                "request_id": self.request_id, "value": value}
        if name != "request.json":
            mail["request"] = self._request
        raw = _encode(mail)
        if len(raw) > MAX_FILE:
            raise ValueError("KDE Connect signed envelope exceeds 65536 bytes")
        filename = f"navi-auth-{name[:-5]}-{self.request_id}.json"
        self._rpc("send", filename=filename, data_b64=base64.b64encode(raw).decode(), request_id=self.request_id)

    def read(self, name):
        if name != "response.json":
            raise ValueError("Invalid phone response name")
        return self._rpc("read") if self.request_id is not None else None

    def notify(self, request_id, canceled=False):
        pass  # Delivery to the phone's DocumentsProvider posts/withdraws the notification.

    def close(self):
        with self._lock:
            process, self._process = self._process, None
            if process is None:
                return
            try:
                process.stdin.close()
                process.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.terminate()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=1)
            finally:
                process.stdout.close()


def _spool_file(filename, raw):
    """All filesystem work in this function runs after dropping desktop UID."""
    runtime = os.environ["XDG_RUNTIME_DIR"]
    if not os.path.isabs(runtime):
        raise ValueError("Invalid desktop runtime directory")
    runtime_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(runtime_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Unsafe desktop runtime directory")
        try:
            os.mkdir("navi-auth-kdeconnect", 0o700, dir_fd=runtime_fd)
        except FileExistsError:
            pass
        directory = os.open("navi-auth-kdeconnect", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=runtime_fd)
    finally:
        os.close(runtime_fd)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Unsafe KDE Connect spool directory")
        count = 0
        total = 0
        cutoff = time.time() - RETENTION_SECONDS
        with os.scandir(directory) as entries:
            for examined, entry in enumerate(entries):
                if examined >= MAX_SPOOL_FILES * 2:
                    raise ValueError("KDE Connect spool has too many entries")
                info = entry.stat(follow_symlinks=False)
                if not MAIL_FILE.fullmatch(entry.name) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError("Unexpected file in KDE Connect spool")
                if info.st_mtime < cutoff:
                    os.unlink(entry.name, dir_fd=directory)
                    continue
                count += 1
                total += info.st_size
        if count >= MAX_SPOOL_FILES or total + len(raw) > MAX_SPOOL_FILES * MAX_FILE:
            raise ValueError("KDE Connect spool is full")
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
        except BaseException:
            os.unlink(filename, dir_fd=directory)
            raise
        return (Path(runtime) / "navi-auth-kdeconnect" / filename).as_uri()
    finally:
        os.close(directory)


def _read_shared_file(uri, request_id):
    if not isinstance(uri, str) or len(uri) > 8192:
        return None
    parts = urlsplit(uri)
    if parts.scheme != "file" or parts.netloc or parts.query or parts.fragment:
        return None
    path = unquote(parts.path, errors="strict")
    if not path.startswith("/") or any(ord(c) < 32 for c in path):
        return None
    # This also allows KDE's collision suffix; the signed body remains authority.
    filename = os.path.basename(path)
    if not filename.startswith(f"navi-auth-response-{request_id}") or not filename.endswith(".json"):
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 0 < info.st_size <= MAX_FILE:
            return None
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            return None
        value = _object(raw)
        return value if value.get("request_id") == request_id else None
    finally:
        os.close(fd)


def _worker(device_id):
    if os.getuid() == 0 or os.geteuid() == 0 or not DEVICE_PATH_ID.fullmatch(device_id):
        raise ValueError("Transport worker requires a non-root desktop UID")
    # These already-installed bindings are deliberately imported only in the child.
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus(private=True)
    owner = bus.get_name_owner(SERVICE)  # Never auto-start an absent KDE daemon.
    device_path = "/modules/kdeconnect/devices/" + device_id
    device = bus.get_object(owner, device_path, introspect=False)
    share = bus.get_object(owner, device_path + "/share", introspect=False)
    daemon = bus.get_object(owner, "/modules/kdeconnect", introspect=False)
    loop = GLib.MainLoop()
    incoming = bytearray()
    responses = collections.deque(maxlen=8)
    active = {"request_id": None}
    os.set_blocking(0, False)
    os.set_blocking(1, False)

    def emit(value):
        data = _encode(value) + b"\n"
        if len(data) > MAX_FRAME:
            raise ValueError("Oversized worker response")
        _write_all(1, data, time.monotonic() + 5)

    def available():
        for name in ("isPaired", "isReachable"):
            if not bool(device.Get("org.kde.kdeconnect.device", name,
                                   dbus_interface="org.freedesktop.DBus.Properties", timeout=5)):
                raise ValueError("The paired phone is not reachable in KDE Connect")
        if not bool(device.isPluginEnabled("kdeconnect_share", dbus_interface="org.kde.kdeconnect.device", timeout=5)):
            raise ValueError("KDE Connect file sharing is disabled for this phone")

    def shared(uri):
        if active["request_id"] is None:
            return
        try:
            value = _read_shared_file(str(uri), active["request_id"])
            if value is not None:
                responses.append(value)
        except (OSError, ValueError, UnicodeError):
            pass  # Untrusted desktop files cannot become protocol errors or authority.

    # dbus-python's add_signal_receiver calls synchronous AddMatch. Only then is
    # hello emitted, so even an immediate phone reply cannot beat subscription.
    subscription = bus.add_signal_receiver(shared, signal_name="shareReceived", dbus_interface=SHARE_INTERFACE,
                                           bus_name=owner, path=device_path + "/share")
    bus.flush()
    desktop_id = str(daemon.selfId(dbus_interface="org.kde.kdeconnect.daemon", timeout=5))
    if not DEVICE_ID.fullmatch(desktop_id):
        raise ValueError("Invalid desktop KDE Connect identity")
    available()

    def command(value):
        operation = value.get("operation")
        if operation == "check":
            available()
        elif operation == "read":
            return responses.popleft() if responses else None
        elif operation == "send":
            filename, request_id = value.get("filename"), value.get("request_id")
            if not isinstance(filename, str) or not MAIL_FILE.fullmatch(filename) or not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
                raise ValueError("Invalid outbound authentication filename")
            if active["request_id"] not in (None, request_id) or not filename.endswith(request_id + ".json"):
                raise ValueError("Transport request mismatch")
            raw = base64.b64decode(value["data_b64"], validate=True)
            if not 0 < len(raw) <= MAX_FILE:
                raise ValueError("Oversized outbound authentication file")
            _object(raw)
            active["request_id"] = request_id
            uri = _spool_file(filename, raw)
            share.shareUrl(uri, dbus_interface=SHARE_INTERFACE, timeout=5)
        else:
            raise ValueError("Unknown transport operation")
        return None

    def stdin_ready(fd, condition):
        try:
            chunk = os.read(fd, 8192)
            if not chunk:
                loop.quit()
                return False
            incoming.extend(chunk)
            if len(incoming) > MAX_FRAME:
                raise ValueError("Oversized transport command")
            while b"\n" in incoming:
                raw, _, remainder = incoming.partition(b"\n")
                incoming[:] = remainder
                try:
                    emit({"ok": True, "value": command(_object(raw))})
                except Exception as error:
                    emit({"ok": False, "error": str(error)[:180]})
            return True
        except BlockingIOError:
            return True
        except Exception:
            loop.quit()
            return False

    GLib.io_add_watch(0, GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, stdin_ready)
    emit({"ok": True, "desktop_device_id": desktop_id})
    try:
        loop.run()
    finally:
        subscription.remove()
        bus.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--worker":
            raise ValueError("This module is used through KdeConnectPhone")
        _worker(sys.argv[2])
    except Exception as error:
        try:
            _write_all(1, _encode({"ok": False, "error": str(error)[:180]}) + b"\n", time.monotonic() + 1)
        except Exception:
            pass
        raise SystemExit(1)
