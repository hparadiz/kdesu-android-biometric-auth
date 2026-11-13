#!/usr/bin/env python3
"""Remote approvals over an ntfy server (navi-remote/v1).

Used only when KDE Connect reports the phone unreachable (or delivery on the normal route
fails). Both sides make outgoing HTTPS connections to the ntfy server: the computer publishes
to the phone's inbox topic and reads its own inbox topic. Topic names and the message key come
from an authenticated ECDH handshake (remote setup) and are never transmitted.

Every message is DEFLATE-compressed, then AES-256-GCM encrypted, bound to its direction and
topic. The relay sees only random topic names, timing and sizes. Nothing received here is
authorization: requests stay machine-signed and responses phone-signed, and callers verify
them exactly as for the other routes.

The HTTP client runs in a worker process as the desktop user (`--worker`); it only moves
opaque ciphertext. The parent holds the key. Importing this module starts nothing.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import select
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from urllib.parse import quote, urlsplit


PROTOCOL = "navi-remote/v1"
INTERPRETER = "/usr/bin/python3"
DEFAULT_SERVER = "https://ntfy.sh"
TO_PHONE = "to-phone"
TO_COMPUTER = "to-computer"
INLINE_LIMIT = 3800          # ntfy message bodies above 4096 bytes become attachments
MAX_PLAIN = 65536            # inflated message cap
MAX_BLOB = 98304             # encrypted message / attachment cap
MAX_LINE = 262144            # one JSON line from the ntfy stream or the worker
RPC_SECONDS = 15
CONNECT_SECONDS = 8
TOPIC = re.compile(r"navi-[a-z2-7]{26}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")


# --- Protocol helpers (shared with the Android implementation) ---------------------------
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text):
    if not isinstance(text, str) or not B64URL.fullmatch(text):
        raise ValueError("Invalid remote message encoding")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(ikm, salt, info, length):
    """RFC 5869 HKDF-SHA256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def topic_name(material):
    return "navi-" + base64.b32encode(material).decode("ascii").rstrip("=").lower()


def derive(shared_secret, setup_request_id):
    """Message key and both inbox topics from the setup ECDH secret; never transmitted."""
    salt = setup_request_id.encode("ascii")
    return dict(key=hkdf(shared_secret, salt, b"navi-remote/v1 key", 32),
                phone_topic=topic_name(hkdf(shared_secret, salt, b"navi-remote/v1 phone-inbox", 16)),
                computer_topic=topic_name(hkdf(shared_secret, salt, b"navi-remote/v1 computer-inbox", 16)))


def aad(direction, topic):
    return f"{PROTOCOL}\n{direction}\n{topic}".encode("ascii")


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate remote message field")
        result[name] = value
    return result


def seal(key, direction, topic, value):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plain = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(plain) > MAX_PLAIN:
        raise ValueError("Remote message is too large")
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, zlib.compress(plain, 9), aad(direction, topic))


def open_sealed(key, direction, topic, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not 12 + 16 <= len(blob) <= MAX_BLOB:
        raise ValueError("Invalid remote message size")
    compressed = AESGCM(key).decrypt(blob[:12], blob[12:], aad(direction, topic))
    inflater = zlib.decompressobj()
    plain = inflater.decompress(compressed, MAX_PLAIN + 1)
    if len(plain) > MAX_PLAIN or inflater.unconsumed_tail or not inflater.eof:
        raise ValueError("Remote message inflates beyond its limit")
    value = json.loads(plain, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("Invalid remote message")
    return value


def validate_server(url):
    """https:// ntfy base URL (http:// only for a loopback test server)."""
    if not isinstance(url, str) or len(url) > 200:
        raise ValueError("Invalid ntfy server URL")
    parts = urlsplit(url.rstrip("/"))
    if parts.query or parts.fragment or parts.username or parts.password or not parts.hostname:
        raise ValueError("The ntfy server URL must be like https://ntfy.sh")
    if parts.scheme != "https":
        try:
            loopback = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            loopback = parts.hostname == "localhost"
        if parts.scheme != "http" or not loopback:
            raise ValueError("The ntfy server must use https://")
    if parts.path and not re.fullmatch(r"(/[A-Za-z0-9._~-]+)*", parts.path):
        raise ValueError("Invalid ntfy server path")
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("Invalid remote approval configuration")
    server = validate_server(config.get("server"))
    token = config.get("token")
    if token is not None and (not isinstance(token, str) or not TOKEN.fullmatch(token)):
        raise ValueError("Invalid ntfy access token")
    for name in ("phone_topic", "computer_topic"):
        if not isinstance(config.get(name), str) or not TOPIC.fullmatch(config[name]):
            raise ValueError("Invalid remote topic")
    key = config.get("key")
    if isinstance(key, str):
        key = base64.b64decode(key, validate=True)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Invalid remote message key")
    return dict(server=server, token=token, phone_topic=config["phone_topic"],
                computer_topic=config["computer_topic"], key=key)


# --- Worker: plain HTTP as the desktop user ---------------------------------------------
def _worker():
    import ssl
    import urllib.request

    output_lock = threading.Lock()

    def emit(value):
        data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        with output_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    line = sys.stdin.buffer.readline(MAX_LINE)
    config = json.loads(line)
    server = validate_server(config["server"])
    token = config.get("token")
    headers = {"User-Agent": "navi-auth"}
    if token:
        headers["Authorization"] = "Bearer " + token
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    server_host = urlsplit(server).netloc

    def request(method, url, body=None, extra=None, timeout=RPC_SECONDS):
        return opener.open(urllib.request.Request(url, data=body, method=method, headers={**headers, **(extra or {})}),
                           timeout=timeout)

    def fetch_attachment(url):
        parts = urlsplit(url)
        if parts.scheme != urlsplit(server).scheme or parts.netloc != server_host:
            raise ValueError("Attachment is not on the configured ntfy server")
        with request("GET", url) as response:
            data = response.read(MAX_BLOB + 1)
        if len(data) > MAX_BLOB:
            raise ValueError("Oversized attachment")
        return data

    def subscribe(topic, since):
        delay = 1
        while True:
            try:
                url = f"{server}/{quote(topic)}/json?since={quote(str(since))}"
                with request("GET", url, timeout=75) as stream:
                    delay = 1
                    while True:
                        raw = stream.readline(MAX_LINE + 1)
                        if not raw:
                            break
                        if len(raw) > MAX_LINE:
                            raise ValueError("Oversized ntfy event")
                        event = json.loads(raw)
                        kind = event.get("event")
                        if kind == "open":
                            emit({"event": "status", "connected": True})
                        elif kind == "message" and event.get("topic") == topic:
                            since = event.get("id", since)
                            attachment = event.get("attachment") or {}
                            try:
                                if attachment.get("url"):
                                    emit({"event": "blob", "data": base64.b64encode(fetch_attachment(attachment["url"])).decode()})
                                elif isinstance(event.get("message"), str):
                                    emit({"event": "text", "data": event["message"]})
                            except Exception as error:
                                emit({"event": "status", "connected": True, "error": type(error).__name__})
            except Exception as error:
                emit({"event": "status", "connected": False, "error": f"{type(error).__name__}: {error}"[:200]})
            time.sleep(delay)
            delay = min(15, delay * 2)

    if config.get("subscribe"):
        topic = config["subscribe"]
        if not TOPIC.fullmatch(topic):
            raise ValueError("Invalid remote topic")
        threading.Thread(target=subscribe, args=(topic, config.get("since", "all")), daemon=True).start()

    while True:
        raw = sys.stdin.buffer.readline(MAX_LINE + 1)
        if not raw:
            os._exit(0)
        command = json.loads(raw)
        seq = command.get("seq")
        try:
            topic = command["topic"]
            if not TOPIC.fullmatch(topic):
                raise ValueError("Invalid remote topic")
            url = f"{server}/{quote(topic)}"
            if "text" in command:
                body = command["text"].encode("ascii")
                if len(body) > INLINE_LIMIT:
                    raise ValueError("Inline remote message is too large")
                with request("POST", url, body, {"Content-Type": "text/plain"}) as response:
                    response.read(65536)
            else:
                body = base64.b64decode(command["blob"], validate=True)
                if len(body) > MAX_BLOB:
                    raise ValueError("Remote attachment is too large")
                with request("PUT", url, body, {"Filename": "navi.bin"}) as response:
                    response.read(65536)
            emit({"reply": seq, "ok": True})
        except Exception as error:
            emit({"reply": seq, "ok": False, "error": f"{type(error).__name__}: {error}"[:300]})


# --- Parent side -----------------------------------------------------------------------
class RemoteChannel:
    """Encrypting front end for one worker; the key never leaves this process."""

    def __init__(self, config, send_direction, send_topic, receive_direction, receive_topic,
                 account=None, since=None):
        self.config = validate_config(config)
        self.send_direction, self.send_topic = send_direction, send_topic
        self.receive_direction, self.receive_topic = receive_direction, receive_topic
        self._condition = threading.Condition()
        self._write_lock = threading.Lock()
        self._replies = {}
        self._inbox = []
        self._seq = 0
        self.connected = False
        self.last_error = None
        self._closed = False
        desktop = account or pwd.getpwuid(os.getuid())
        if desktop.pw_uid == 0 or (os.geteuid() != 0 and desktop.pw_uid != os.getuid()):
            raise ValueError("Remote approvals require the non-root desktop account")
        options = {}
        if os.geteuid() == 0:
            options.update(user=desktop.pw_uid, group=desktop.pw_gid, extra_groups=[])
        self._process = subprocess.Popen(
            [INTERPRETER, "-I", str(Path(__file__).resolve()), "--worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
            env={"PATH": "/usr/bin:/bin", "HOME": desktop.pw_dir, "LANG": "C.UTF-8"},
            close_fds=True, start_new_session=True, umask=0o077, **options)
        first = dict(server=self.config["server"], token=self.config["token"],
                     subscribe=receive_topic, since=since if since is not None else str(int(time.time()) - 2))
        self._send_line(first)
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _send_line(self, value):
        data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        # A separate lock: the reader thread must never wait behind a blocked pipe write.
        with self._write_lock:
            process = self._process
            if process is None:
                raise ConnectionError("Remote channel is closed")
            process.stdin.write(data)
            process.stdin.flush()

    def _read_loop(self):
        stream = self._process.stdout
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw or len(raw) > MAX_LINE:
                break
            try:
                event = json.loads(raw)
            except ValueError:
                break
            with self._condition:
                if "reply" in event:
                    self._replies[event["reply"]] = event
                elif event.get("event") == "status":
                    self.connected = bool(event.get("connected"))
                    self.last_error = event.get("error")
                elif event.get("event") in ("text", "blob"):
                    try:
                        blob = unb64url(event["data"]) if event["event"] == "text" else base64.b64decode(event["data"], validate=True)
                        self._inbox.append(open_sealed(self.config["key"], self.receive_direction, self.receive_topic, blob))
                    except Exception:
                        pass  # Not ours, corrupted or forged: dropped without a reply.
                self._condition.notify_all()
        with self._condition:
            self.connected = False
            self._closed = True
            self._condition.notify_all()

    def wait_connected(self, timeout=CONNECT_SECONDS):
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self.connected and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            if not self.connected:
                detail = f" ({self.last_error})" if self.last_error else ""
                raise ConnectionError(f"The ntfy server {self.config['server']} is not reachable{detail}")

    def publish(self, value):
        blob = seal(self.config["key"], self.send_direction, self.send_topic, value)
        text = b64url(blob)
        command = {"topic": self.send_topic}
        if len(text) <= INLINE_LIMIT:
            command["text"] = text
        else:
            command["blob"] = base64.b64encode(blob).decode("ascii")
        with self._condition:
            self._seq += 1
            seq = command["seq"] = self._seq
        self._send_line(command)
        deadline = time.monotonic() + RPC_SECONDS
        with self._condition:
            while seq not in self._replies:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._closed:
                    raise TimeoutError("The ntfy server did not accept the message in time")
                self._condition.wait(remaining)
            reply = self._replies.pop(seq)
        if reply.get("ok") is not True:
            raise ConnectionError("ntfy publish failed: " + str(reply.get("error")))

    def drain(self):
        with self._condition:
            messages, self._inbox = self._inbox, []
        return messages

    def close(self):
        with self._write_lock:
            process, self._process = self._process, None
        if process is None:
            return
        try:
            process.stdin.close()
            process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=1)
        finally:
            process.stdout.close()


class RemotePhone:
    """NetworkPhone-compatible adapter for one request over ntfy (computer side)."""
    transport_kind = "ntfy"

    def __init__(self, crypto, config, machine_key, root, leaf, account=None):
        crypto.validate_certificate(leaf, root)
        self.crypto, self.key, self.root, self.leaf = crypto, machine_key, root, leaf
        self.phone_id = crypto.digest(crypto.spki(leaf.public_key()))
        self.config = validate_config(config)
        self.account = account
        self.channel = None
        self.request = None
        self.raw = None
        self.request_id = None
        self.response = None
        self.icon_png = None
        self.icon_sha256 = None
        self.icons_sent = 0

    def _channel(self):
        if self.channel is None:
            self.channel = RemoteChannel(self.config, TO_PHONE, self.config["phone_topic"],
                                         TO_COMPUTER, self.config["computer_topic"], self.account)
        return self.channel

    def check(self):
        self._channel().wait_connected()
        return self.identity()

    def identity(self):
        return dict(key_id_sha256=self.phone_id,
                    public_key_spki_base64=self.crypto.b64(self.crypto.spki(self.leaf.public_key())))

    def set_icon(self, png):
        """The PNG whose hash the signed request carries; sent only when Navi asks for it."""
        self.icon_png = png or None
        self.icon_sha256 = hashlib.sha256(png).hexdigest() if png else None

    def adopt_request(self, value):
        self.request = value
        self.raw = self.crypto.unb64(value["payload_b64"])
        self.request_id = json.loads(self.raw)["request_id"]

    def write(self, name, value):
        channel = self._channel()
        if name == "request.json":
            self.adopt_request(value)
            if not self.raw.isascii():
                raise ValueError("Signed payload must be canonical ASCII JSON")
            message = {"name": name, "request_id": self.request_id,
                       "value": {"payload_json": self.raw.decode("ascii"), "signature_b64": value["signature_b64"],
                                 "machine_certificate_b64": value["machine_certificate_b64"],
                                 "phone_certificate_b64": value["phone_certificate_b64"]}}
        elif name in ("receipt.json", "cancel.json"):
            if self.raw is None:
                raise ValueError("A terminal message requires its original signed request")
            # By reference: Navi already holds the request it is answering.
            message = {"name": name, "request_id": self.request_id, "value": value,
                       "request_sha256": self.crypto.digest(self.raw)}
        else:
            raise ValueError("Invalid computer message name")
        channel.publish(message)

    def read(self, name):
        if name != "response.json":
            raise ValueError("Invalid phone response name")
        for message in self._channel().drain():
            if message.get("request_id") != self.request_id:
                continue
            if message.get("name") == "icon-request":
                if (self.icon_png and message.get("icon_sha256") == self.icon_sha256 and self.icons_sent < 2):
                    self.icons_sent += 1
                    try:
                        self.channel.publish({"name": "icon", "request_id": self.request_id,
                                              "icon_png_base64": self.crypto.b64(self.icon_png)})
                    except Exception:
                        pass  # Optional: Navi keeps its default icon.
            elif message.get("name") == "response.json" and self.response is None:
                status = message.get("status")
                if status == "signed":
                    response = {"request_id": self.request_id, "status": "signed",
                                "payload_b64": self.crypto.b64(self.raw),
                                "signature_b64": message.get("signature_b64"),
                                "phone_certificate_b64": self.request["phone_certificate_b64"]}
                    if "phone_ecdh_spki_b64" in message:
                        response["phone_ecdh_spki_b64"] = message["phone_ecdh_spki_b64"]
                    self.response = response
                elif status == "declined":
                    self.response = {"request_id": self.request_id, "status": "declined",
                                     "message": str(message.get("message", ""))[:200]}
        return self.response

    def notify(self, request_id, canceled=False):
        pass  # Navi posts or withdraws its notification when the message arrives.

    def close(self):
        if self.channel is not None:
            self.channel.close()


class RoutedPhone:
    """Chooses the route per request: the normal route when KDE Connect sees the phone,
    ntfy when it does not (or when delivery on the normal route fails)."""

    def __init__(self, make_primary, make_remote, log=None, probe=None):
        self._make_primary, self._make_remote = make_primary, make_remote
        # Optional liveness check: KDE Connect may still call a phone reachable after it left Wi-Fi.
        self._probe = probe
        self._log = log or (lambda message: None)
        self.primary = None
        self.remote = None
        self.route = None
        self._request = None
        self.remote_binding = {"kind": "ntfy"}

    @property
    def transport(self):
        if self.primary is not None and hasattr(self.primary, "transport"):
            return self.primary.transport
        raise AttributeError("transport")

    def _use_remote(self, reason):
        if self.remote is None:
            remote = self._make_remote()
            try:
                remote.check()
            except BaseException:
                remote.close()
                raise
            self.remote = remote
        if self._request is not None and self.remote.request is None:
            self.remote.adopt_request(self._request)
        if self.route != "remote":
            self._log(f"route=ntfy ({reason})")
        self.route = "remote"

    def check(self):
        try:
            self.primary = self._make_primary()
            identity = self.primary.check()
            if self._probe is not None:
                try:
                    present = self._probe()
                except Exception as error:
                    present = None  # Can't tell: trust KDE Connect.
                    self._log(f"probe failed, trusting KDE Connect ({type(error).__name__}: {error})"[:300])
                self._log(f"probe present={present}")
                if present is False:
                    raise ConnectionError("KDE Connect lists the phone, but it does not answer on the local network")
            self.route = "primary"
            self._log("route=primary")
            return identity
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"[:160]
            try:
                self._use_remote(reason)
            except Exception as remote_error:
                raise ConnectionError(f"The phone is not reachable on the local network ({error}) and remote "
                                      f"approvals over ntfy failed ({remote_error})") from remote_error
            return self.remote.identity()

    def identity(self):
        return (self.remote if self.route == "remote" else self.primary).identity()

    def set_icon(self, png):
        if self.remote is not None:
            self.remote.set_icon(png)

    def write(self, name, value):
        if name == "request.json":
            self._request = value
        if self.route == "primary":
            try:
                return self.primary.write(name, value)
            except Exception as error:
                self._use_remote(f"delivery failed: {type(error).__name__}")
        return self.remote.write(name, value)

    def read(self, name):
        if self.route == "primary":
            try:
                return self.primary.read(name)
            except Exception as error:
                # The normal route dropped mid-request: listen on ntfy, where Navi's
                # "Send approval again" can still reach this computer.
                self._use_remote(f"reply route failed: {type(error).__name__}")
        return self.remote.read(name)

    def notify(self, request_id, canceled=False):
        if self.route == "primary":
            self.primary.notify(request_id, canceled)

    def close(self):
        for phone in (self.primary, self.remote):
            if phone is not None and hasattr(phone, "close"):
                try:
                    phone.close()
                except Exception:
                    pass


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        try:
            _worker()
        except Exception as error:
            sys.stdout.write(json.dumps({"event": "status", "connected": False, "error": str(error)[:200]}) + "\n")
            sys.stdout.flush()
            raise SystemExit(1)
    raise SystemExit("Usage: ntfy_transport.py --worker")
