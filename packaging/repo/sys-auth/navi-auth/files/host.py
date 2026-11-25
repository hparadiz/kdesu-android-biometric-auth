#!/usr/bin/env python3
"""Machine-issued phone credentials and biometric verification over signed LAN or ADB."""
import argparse
import base64
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import sqlite3
import subprocess
import sys
import time
import uuid
import ssl
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PACKAGE = "in.akuj.fingerprint"
DOMAIN = "android-linux-fingerprint/v1"
STATE = Path(__file__).resolve().parent / ".state"
TTL = 120


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def encode(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def certificate(key, issuer, issuer_key, common_name, ca=False):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject).public_key(key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650 if ca else 365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def machine_identity(create=False):
    key_path = STATE / "machine-key.pem"
    cert_path = STATE / "machine-cert.pem"
    if not key_path.exists():
        if not create:
            raise ValueError("Initialize this machine with: ./host.py init")
        if cert_path.exists():
            raise ValueError("Machine private key is missing. Refusing to silently change its identity.")
        key = ec.generate_private_key(ec.SECP256R1())
        atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if key_path.stat().st_mode & 0o077:
        raise ValueError("Machine private key must be accessible only to its owner (chmod 600).")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not cert_path.exists():
        if not create:
            raise ValueError("Machine certificate is missing. Run ./host.py init to recover it.")
        root = certificate(key.public_key(), None, key, socket.gethostname(), ca=True)
        atomic_write(cert_path, root.public_bytes(serialization.Encoding.PEM))
    root = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if spki(root.public_key()) != spki(key.public_key()):
        raise ValueError("Machine certificate does not match the private key.")
    validate_certificate(root, root, ca=True)
    return key, root


def validate_certificate(cert, root, ca=False):
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("Certificate is expired or not yet valid.")
    if cert.issuer != root.subject:
        raise ValueError("Certificate issuer mismatch.")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca != ca:
        raise ValueError("Certificate has the wrong CA role.")
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature or usage.key_cert_sign != ca:
        raise ValueError("Certificate has the wrong key usage.")
    if not isinstance(cert.public_key(), ec.EllipticCurvePublicKey) or not isinstance(cert.public_key().curve, ec.SECP256R1):
        raise ValueError("Only P-256 certificates are accepted.")
    if not isinstance(cert.signature_hash_algorithm, hashes.SHA256):
        raise ValueError("Only SHA-256 certificate signatures are accepted.")
    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))


class Phone:
    def __init__(self, serial):
        self.serial = serial
        model = self.adb("shell", "getprop", "ro.product.model").decode().strip()
        if not model.startswith("Pixel") and model != "Nexus 6P":
            raise ValueError(f"Expected the selected Pixel or Nexus 6P; found {model!r}.")
        sdk = int(self.adb("shell", "getprop", "ro.build.version.sdk").decode().strip())
        if sdk < 28:
            raise ValueError("Android 9 or newer is required.")

    def adb(self, *args, data=None, optional=False):
        result = subprocess.run(["adb", "-s", self.serial, *args], input=data,
                                capture_output=True, timeout=15)
        if result.returncode and not optional:
            raise RuntimeError(result.stderr.decode(errors="replace").strip() or "ADB command failed")
        return result.stdout if result.returncode == 0 else b""

    def read(self, name):
        # shell v2 preserves the remote exit status/stderr; exec-out reports a
        # missing file's error text as stdout with success, which is not JSON.
        raw = self.adb("shell", "-T", "run-as", PACKAGE, "cat", "files/" + name, optional=True)
        if len(raw) > 65536:
            raise ValueError("Phone response exceeds the size limit.")
        return json.loads(raw) if raw else None

    def write(self, name, value):
        # Fixed filenames, payload via stdin, and no user text interpolated into a shell.
        if name not in {"request.json", "receipt.json", "cancel.json"}:
            raise ValueError("Unexpected bridge filename.")
        if len(encode(value)) > 65536:
            raise ValueError("Computer message exceeds the size limit.")
        temporary = "files/" + name + ".tmp"
        self.adb("shell", "-T", "run-as", PACKAGE, "sh", "-c",
                 "'cat > " + temporary + " && mv " + temporary + " files/" + name + "'", data=encode(value))

    def identity(self):
        for _ in range(15):
            value = self.read("identity.json")
            if value:
                return value
            time.sleep(1)
        raise ValueError("The app has not published its key. Check its on-screen status and biometric enrollment.")

    def notify(self, request_id, canceled=False):
        self.adb("shell", "am", "broadcast", "-n", PACKAGE + "/.RequestReceiver",
                 "-a", PACKAGE + (".REQUEST_CANCELED" if canceled else ".REQUEST_READY"),
                 "--es", "request_id", request_id)


class NetworkPhone:
    """TLS connection pinned through the already-approved biometric phone key.

    The TLS self-signed certificate is NOT trusted on first use. Before sending
    any RPC, verify its biometric signature and exact match to the live TLS peer.
    The encrypted RPC is separately machine-signed and bound to a server nonce.
    """
    def __init__(self, endpoint, machine_key, root, leaf, resolve_endpoint=None):
        self.resolve_endpoint = resolve_endpoint
        self.refreshed = False
        self._set_endpoint(endpoint if endpoint is not None else resolve_endpoint())
        validate_certificate(leaf, root)
        self.key, self.root, self.leaf = machine_key, root, leaf
        self.machine_id = digest(spki(root.public_key()))
        self.phone_id = digest(spki(leaf.public_key()))
        self.request_id = None

    def _set_endpoint(self, endpoint):
        import ipaddress
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("Expected a phone IP:port endpoint")
        address = ipaddress.ip_address(host.strip("[]"))
        if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError("Phone endpoint must be a private LAN address")
        self.address = (str(address), int(port))

    @staticmethod
    def _read(stream):
        raw = stream.readline(131073)
        if len(raw) > 131072 or not raw.endswith(b"\n"):
            raise ValueError("Invalid network frame")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Invalid network object")
        return value

    def _connect(self):
        deadline = time.monotonic() + 15
        try:
            return self._connect_once(deadline)
        except OSError:
            if self.resolve_endpoint is None or self.refreshed:
                raise
            # Retry only connection establishment, before any RPC was sent.
            # One discovery refresh per request; keep the original time bound.
            self.refreshed = True
            self._set_endpoint(self.resolve_endpoint(refresh=True,
                previous=f"{self.address[0]}:{self.address[1]}",
                timeout=min(5, max(0, deadline - time.monotonic()))))
            return self._connect_once(deadline)

    def _connect_once(self, deadline):
        # Custom trust: the known biometric key certifies the transport key.
        # CERT_NONE suppresses Web PKI validation only; no RPC is sent until our
        # mandatory pinned-key verification below succeeds on this same socket.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Android 9 needs TLS 1.2; keep its suites forward-secret and AEAD-only.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Phone connection timed out after network discovery")
        raw_socket = socket.create_connection(self.address, timeout=min(5, remaining))
        connection = None
        stream = None
        sockets = [raw_socket]
        def expire():
            try:
                sockets[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        watchdog = threading.Timer(max(0, min(10, deadline - time.monotonic())), expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection = context.wrap_socket(raw_socket, do_handshake_on_connect=False)
            sockets[0] = connection
            connection.do_handshake()
            stream = connection.makefile("rwb")
            hello = self._read(stream)
            identity = hello["identity"]
            payload = unb64(identity["payload_b64"])
            self.leaf.public_key().verify(unb64(identity["signature_b64"]), payload, ec.ECDSA(hashes.SHA256()))
            statement = json.loads(payload)
            if statement.get("domain") != DOMAIN or statement.get("kind") != "network-identity" or statement.get("phone_key_id") != self.phone_id:
                raise ValueError("Network identity does not match the approved phone")
            if unb64(statement["tls_certificate_b64"]) != connection.getpeercert(binary_form=True):
                raise ValueError("TLS peer is not the phone's biometrically approved transport")
            if len(unb64(hello["nonce"])) != 32:
                raise ValueError("Invalid server challenge")
            validate_certificate(self.leaf, self.root)
            return connection, stream, hello["nonce"], watchdog
        except BaseException:
            watchdog.cancel()
            if stream is not None:
                stream.close()
            if connection is not None:
                connection.close()
            raw_socket.close()
            raise

    def check(self):
        connection, stream, _, watchdog = self._connect()
        watchdog.cancel()
        stream.close()
        connection.close()
        return self.identity()

    def identity(self):
        return dict(key_id_sha256=self.phone_id, public_key_spki_base64=b64(spki(self.leaf.public_key())))

    def _exchange(self, operation, name, value=None):
        connection, stream, nonce, watchdog = self._connect()
        try:
            payload = dict(domain=DOMAIN, kind="network-rpc", machine_id=self.machine_id,
                           phone_key_id=self.phone_id, server_nonce=nonce, operation=operation,
                           name=name, request_id=self.request_id, value=value)
            raw = encode(envelope(self.key, payload)) + b"\n"
            if len(raw) > 131072:
                raise ValueError("Network request exceeds size limit")
            stream.write(raw)
            stream.flush()
            result = self._read(stream)
            if result.get("ok") is not True:
                raise ValueError("Phone rejected the network request")
            return result.get("value")
        finally:
            watchdog.cancel()
            stream.close()
            connection.close()

    def write(self, name, value):
        if name not in {"request.json", "receipt.json", "cancel.json"} or len(encode(value)) > 65536:
            raise ValueError("Invalid computer message")
        if name == "request.json":
            self.request_id = json.loads(unb64(value["payload_b64"]))["request_id"]
        self._exchange("write", name, value)

    def read(self, name):
        if name != "response.json":
            raise ValueError("Invalid response name")
        return self._exchange("read", name)

    def notify(self, request_id, canceled=False):
        pass  # The phone validates and posts/withdraws its notification on delivery.


def kdeconnect_endpoint(device_id, environment=None, account=None, *, refresh=False, previous=None, timeout=5):
    """Use the desktop's paired KDE Connect device only as a live address book."""
    import ipaddress
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", device_id):
        raise ValueError("Invalid KDE Connect device ID")
    options = {}
    if account is not None:
        options = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/",
                       env={"PATH": "/usr/bin:/bin", "HOME": account.pw_dir,
                            "DBUS_SESSION_BUS_ADDRESS": environment.get("DBUS_SESSION_BUS_ADDRESS", ""),
                            "XDG_RUNTIME_DIR": f"/run/user/{account.pw_uid}"})
    deadline = time.monotonic() + timeout
    def call(path, *arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Phone network discovery timed out")
        result = subprocess.run(["/usr/bin/qdbus6", "org.kde.kdeconnect", path, *arguments],
            capture_output=True, timeout=remaining, check=True, **options)
        if len(result.stdout) > 4096:
            raise ValueError("Oversized KDE Connect reply")
        return result.stdout.decode().strip()
    def property_value(name):
        return call("/modules/kdeconnect/devices/" + device_id,
            "org.freedesktop.DBus.Properties.Get", "org.kde.kdeconnect.device", name)
    if property_value("isPaired") != "true":
        raise ValueError("The phone is not paired in KDE Connect")
    def current_endpoint():
        if property_value("isReachable") == "true":
            for candidate in property_value("reachableAddresses").splitlines():
                try:
                    address = ipaddress.ip_address(candidate.strip())
                except ValueError:
                    continue
                if address.version == 4 and address.is_private and not address.is_loopback and not address.is_unspecified and not address.is_multicast:
                    return f"{address}:39841"
        return None
    if not refresh:
        endpoint = current_endpoint()
        if endpoint:
            return endpoint
    # Reuse KDE Connect's UDP/mDNS discovery once, then inspect local state.
    call("/modules/kdeconnect", "org.kde.kdeconnect.daemon.forceOnNetworkChange")
    endpoint = None
    for delay in (0, 0.25, 0.5, 1, 2):
        if deadline - time.monotonic() <= delay:
            break
        time.sleep(delay)
        endpoint = current_endpoint()
        if endpoint and endpoint != previous:
            return endpoint
    if endpoint:
        return endpoint
    raise ConnectionError("Phone not found after KDE Connect network discovery")


def kdeconnect_addresses(device_id, environment=None, account=None, timeout=5):
    """IP addresses KDE Connect currently associates with the paired device (may be stale)."""
    import ipaddress
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", device_id):
        raise ValueError("Invalid KDE Connect device ID")
    options = {}
    if account is not None:
        options = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/",
                       env={"PATH": "/usr/bin:/bin", "HOME": account.pw_dir,
                            "DBUS_SESSION_BUS_ADDRESS": (environment or {}).get("DBUS_SESSION_BUS_ADDRESS", ""),
                            "XDG_RUNTIME_DIR": f"/run/user/{account.pw_uid}"})
    result = subprocess.run(["/usr/bin/qdbus6", "org.kde.kdeconnect", "/modules/kdeconnect/devices/" + device_id,
                             "org.freedesktop.DBus.Properties.Get", "org.kde.kdeconnect.device", "reachableAddresses"],
                            capture_output=True, timeout=timeout, check=True, **options)
    addresses = []
    for candidate in result.stdout.decode(errors="replace").split()[:8]:
        try:
            address = ipaddress.ip_address(candidate.strip())
        except ValueError:
            continue
        if address.is_private and not address.is_loopback and not address.is_unspecified and not address.is_multicast:
            addresses.append(str(address))
    return addresses


def lan_present(addresses, timeout=2.0, ports=(1716, 39841)):
    """Whether the phone answers on the local network right now.

    KDE Connect can report a phone as reachable for a while after it left Wi-Fi. A TCP
    connection to its KDE Connect (1716) or Navi (39841) port that connects *or is refused*
    proves the device is on the network; only timeouts and "host unreachable" count as absent.
    Returns None when there is no address to test (e.g. a Bluetooth link): trust KDE Connect.
    """
    if not addresses:
        return None
    present = threading.Event()
    def probe(host, port):
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            present.set()
        except ConnectionRefusedError:
            present.set()
        except OSError:
            pass
    workers = [threading.Thread(target=probe, args=(host, port), daemon=True) for host in addresses for port in ports]
    for worker in workers:
        worker.start()
    deadline = time.monotonic() + timeout + 0.2
    for worker in workers:
        worker.join(max(0, deadline - time.monotonic()))
        if present.is_set():
            return True
    return present.is_set()


def envelope(key, payload):
    raw = encode(payload)
    return {"payload_b64": b64(raw), "signature_b64": b64(key.sign(raw, ec.ECDSA(hashes.SHA256())))}


def validate_context(context):
    for name, limit, empty in (("application", 80, False), ("action_id", 160, False),
            ("command", 512, True), ("requesting_user", 64, False), ("target_user", 64, False),
            ("source", 64, False), ("icon_name", 128, True)):
        value = context.get(name, "")
        if not isinstance(value, str) or (not empty and not value) or len(value) > limit or any(
                ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or 0x202a <= ord(c) <= 0x202e
                or 0x2066 <= ord(c) <= 0x2069 for c in value):
            raise ValueError(f"Invalid {name} display metadata.")
    if type(context.get("requesting_uid")) is not int or context["requesting_uid"] != os.getuid():
        raise ValueError("Requesting UID must match this session.")
    if "command_hidden" in context and type(context["command_hidden"]) is not bool:
        raise ValueError("command_hidden must be boolean.")
    if context.get("command_hidden") and context.get("command"):
        raise ValueError("Hidden command must be empty.")
    if "icon_sha256" in context and (not isinstance(context["icon_sha256"], str)
                                     or not re.fullmatch(r"[0-9a-f]{64}", context["icon_sha256"])):
        raise ValueError("Invalid requester icon hash.")
    encoded = context.get("icon_png_base64", "")
    if not isinstance(encoded, str) or len(encoded) > 22000:
        raise ValueError("Requester icon is too large.")
    if encoded:
        icon = unb64(encoded)
        if len(icon) < 24 or len(icon) > 16384 or icon[:8] != b"\x89PNG\r\n\x1a\n" or icon[12:16] != b"IHDR":
            raise ValueError("Requester icon must be a PNG thumbnail of at most 16 KiB.")
        width, height = struct.unpack(">II", icon[16:24])
        if not 1 <= width <= 256 or not 1 <= height <= 256:
            raise ValueError("Requester icon dimensions must not exceed 256x256.")


def kdeconnect_module():
    spec = importlib.util.spec_from_file_location("navi_kdeconnect_transport", Path(__file__).with_name("kdeconnect_transport.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kdeconnect_transport():
    return kdeconnect_module().KdeConnectPhone


_REMOTE_MODULE = None


def remote_module():
    global _REMOTE_MODULE
    if _REMOTE_MODULE is None:
        spec = importlib.util.spec_from_file_location("navi_ntfy_transport", Path(__file__).with_name("ntfy_transport.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _REMOTE_MODULE = module
    return _REMOTE_MODULE


def remote_config(db, key_id):
    """Remote approval (ntfy) settings for an approved phone, or None."""
    try:
        row = db.execute("SELECT server, token, phone_topic, computer_topic, key FROM remote WHERE key_id=?", (key_id,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return dict(server=row[0], token=row[1], phone_topic=row[2], computer_topic=row[3], key=bytes(row[4]))


def remote_servers(db):
    try:
        return dict(db.execute("SELECT key_id, server FROM remote").fetchall())
    except sqlite3.OperationalError:
        return {}


def remote_topic_urls(db):
    """Web addresses of each phone's two ntfy topics, for viewing the (encrypted) traffic."""
    try:
        rows = db.execute("SELECT key_id, server, phone_topic, computer_topic FROM remote").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {key_id: (f"{server.rstrip('/')}/{phone}", f"{server.rstrip('/')}/{computer}") for key_id, server, phone, computer in rows}


# --- Output -----------------------------------------------------------------
# With --json, stdout carries one JSON event per line for the System Settings
# module; human-readable text is suppressed so the stream stays parseable.
JSON_MODE = False


def emit(event, **fields):
    if JSON_MODE:
        sys.stdout.write(json.dumps(dict(event=event, **fields), separators=(",", ":")) + "\n")
        sys.stdout.flush()


def say(text="", **options):
    if not JSON_MODE:
        print(text, flush=True, **options)


# --- Code pairing -------------------------------------------------------------
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: no I, L, O, U
OFFER_TTL = 600


def pairing_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def code_tag(code, label, payload):
    return hmac.new(code.encode("ascii"), label.encode("ascii") + b"\n" + payload, hashlib.sha256).digest()


def verify_hello(hello, code, session_id, machine_id):
    """The phone's key is only accepted with a tag made from the code the user typed."""
    if not isinstance(hello, dict) or hello.get("request_id") != session_id or hello.get("kind") != "enroll-hello":
        return None
    raw = unb64(hello["payload_b64"])
    if len(raw) > 8192 or not hmac.compare_digest(unb64(hello["code_tag_b64"]), code_tag(code, "navi-enroll-hello/v1", raw)):
        raise ValueError("Phone confirmation does not match the pairing code.")
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("domain") != DOMAIN or value.get("kind") != "enroll-hello"
            or value.get("session_id") != session_id or value.get("machine_id") != machine_id):
        raise ValueError("Phone confirmation is for another pairing.")
    public_der = unb64(value["public_key_spki_base64"])
    if value.get("phone_key_id") != digest(public_der):
        raise ValueError("Phone public-key ID mismatch.")
    return dict(key_id_sha256=digest(public_der), public_key_spki_base64=b64(public_der))


def pair_with_code(device, machine_key, root):
    """Offer this machine over KDE Connect and wait for the phone's code-tagged key."""
    transport = kdeconnect_transport()(sys.modules[__name__], device["id"], machine_key, root, None)
    try:
        code = pairing_code()
        session_id = secrets.token_hex(16)
        machine_id = digest(spki(root.public_key()))
        now = int(time.time() * 1000)
        payload = {"domain": DOMAIN, "kind": "enroll-offer", "session_id": session_id,
                   "machine_id": machine_id, "machine_name": socket.gethostname(),
                   "desktop_device_id": transport.transport["desktop_device_id"],
                   "issued_at_ms": now, "expires_at_ms": now + OFFER_TTL * 1000}
        offer = envelope(machine_key, payload)
        offer["machine_certificate_b64"] = b64(root.public_bytes(serialization.Encoding.DER))
        offer["code_tag_b64"] = b64(code_tag(code, "navi-enroll-offer/v1", encode(payload)))
        transport.check()
        transport.send_offer(session_id, offer)
        shown = f"{code[:4]}-{code[4:]}"
        emit("step", step="offer-sent", device_id=device["id"], device_name=device["name"])
        offer_file = f"navi-auth-enroll-offer-{session_id}.json"
        emit("code", code=shown, expires_at_ms=payload["expires_at_ms"], machine_id=machine_id, offer_file=offer_file)
        say(f"\nPair with {device['name']}")
        say("  Open Navi Authenticator on the phone and enter this code:\n")
        say(f"      {shown}\n")
        say(f"  Computer: {socket.gethostname()} · {machine_id[:4]} {machine_id[4:8]} {machine_id[8:12]}"
            f" · expires in {OFFER_TTL // 60} minutes")
        say("  No code box in Navi? KDE Connect isn't delivering to Navi yet. On the phone:")
        say("  Navi → ☰ → Settings → Set up KDE Connect, then press Ctrl+C and run enroll again.")
        say(f"  (Opening {offer_file} from Downloads with Navi shows the same steps.)\n")
        say("  Waiting for the phone…")
        deadline = time.monotonic() + OFFER_TTL
        while time.monotonic() < deadline:
            identity = verify_hello(transport.read_hello(), code, session_id, machine_id)
            if identity:
                emit("step", step="hello-verified", phone_key_id=identity["key_id_sha256"])
                say("Code confirmed on the phone. Sending the pairing request…")
                return identity
            time.sleep(1)
        raise ValueError("The pairing code expired before the phone confirmed it.")
    finally:
        transport.close()


# --- KDE Connect device selection ------------------------------------------------
def enrolled_devices(db):
    return {row[0]: dict(key_id=row[1], device_name=row[2], enrolled_at=row[3])
            for row in db.execute("SELECT kdeconnect_device, key_id, device_name, enrolled_at FROM devices "
                                  "WHERE kdeconnect_device IS NOT NULL AND key_id IN (SELECT key_id FROM approved)")}


def known_devices(db):
    enrolled = enrolled_devices(db)
    remotes = remote_servers(db)
    topics = remote_topic_urls(db)
    devices = kdeconnect_module().list_devices()
    for device in devices:
        record = enrolled.get(device["id"])
        device["enrolled"] = record is not None
        device["phone_key_id"] = record["key_id"] if record else None
        device["remote"] = remotes.get(device["phone_key_id"]) if record else None
        urls = topics.get(device["phone_key_id"]) if record else None
        device["remote_phone_url"], device["remote_computer_url"] = urls if urls else (None, None)
    return devices


def device_label(device):
    state = "reachable" if device["reachable"] else "offline"
    if device["reachable"] and not device["share"]:
        state = "file sharing disabled"
    remote = f" · remote: {device['remote']}" if device.get("remote") else ""
    return f"{device['name']} · {state} · {'enrolled' if device['enrolled'] else 'not enrolled'}{remote}"


def select_device(db, query, purpose):
    """Resolve an ID or name; without one, choose the only candidate or ask on a TTY."""
    try:
        devices = known_devices(db)
    except Exception:
        if query and re.fullmatch(r"[A-Za-z0-9_]{1,128}", query) and purpose != "enroll":
            # KDE Connect listing unavailable: an explicit device ID still routes as before.
            return dict(id=query, name=query, enrolled=False, phone_key_id=None, reachable=True, share=True)
        raise
    if purpose == "enroll":
        usable = lambda device: device["reachable"] and device["share"]
    else:
        usable = lambda device: device["enrolled"]
    listing = "\n".join(f"  {device['id']}  {device_label(device)}" for device in devices) or "  (none)"
    if query:
        matches = [device for device in devices if device["id"] == query]
        matches = matches or [device for device in devices if device["name"] == query]
        matches = matches or [device for device in devices if device["name"].casefold() == query.casefold()]
        if len(matches) != 1:
            raise ValueError(("Several KDE Connect devices are named " if matches else "No paired KDE Connect device matches ")
                             + repr(query) + ". Use the device ID:\n" + listing)
        # A phone enrolled before 0.8 has no device record; --phone-key-id still selects it.
        return matches[0]
    candidates = [device for device in devices if usable(device)]
    if not candidates:
        raise ValueError(("No reachable paired phone with KDE Connect file sharing enabled."
                          if purpose == "enroll" else "No enrolled phone. Run enroll first.")
                         + "\nPaired KDE Connect devices:\n" + listing)
    if len(candidates) == 1:
        say(f"Using {candidates[0]['name']} (id {candidates[0]['id']})")
        return candidates[0]
    if JSON_MODE or not sys.stdin.isatty():
        raise ValueError("Several phones are available; choose one with --kdeconnect-device ID_OR_NAME:\n" + listing)
    for number, device in enumerate(candidates, 1):
        say(f"  {number}) {device_label(device)}")
    for device in devices:
        if device not in candidates:
            say(f"     {device_label(device)}")
    while True:
        answer = input(f"Select device [1-{len(candidates)}]: ").strip()
        if answer.isdecimal() and 1 <= int(answer) <= len(candidates):
            return candidates[int(answer) - 1]
        say("Enter one of the listed numbers, or press Ctrl+C to cancel.")


def approve(args, db, machine_key, root):
    enrolling = args.command == "enroll"
    setup = args.command == "remote-setup"
    for name in ("serial", "endpoint", "kdeconnect_device", "kdeconnect_messages", "phone_key_id", "context_file",
                 "desktop_request_id", "icon_file"):
        if not hasattr(args, name):
            setattr(args, name, None)
    for name in ("notification_only", "remote_only"):
        if not hasattr(args, name):
            setattr(args, name, False)
    for name, value in (("operation", ""), ("application", "Navi remote approvals"), ("action_id", "remote-setup"),
                        ("requested_command", ""), ("target_user", ""), ("icon_name", "network-wireless")):
        if not hasattr(args, name):
            setattr(args, name, value)
    device = None
    leaf = None
    setup_key = None
    if setup:
        # Remote setup travels over the phone's normal route (KDE Connect messages).
        device = select_device(db, args.setup_device, "authenticate")
        args.kdeconnect_messages = device["id"]
        args.phone_key_id = device["phone_key_id"] or args.phone_key_id
        setup_key = ec.generate_private_key(ec.SECP256R1())
    if enrolling and not args.serial:
        # Release enrollment: the code shown here pins this machine on the phone.
        device = select_device(db, args.kdeconnect_device, "enroll")
        identity = pair_with_code(device, machine_key, root)
        public = serialization.load_der_public_key(unb64(identity["public_key_spki_base64"]))
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError("Phone key must be P-256.")
        leaf = certificate(public, root, machine_key, "Phone " + identity["key_id_sha256"][:32])
        phone = kdeconnect_transport()(sys.modules[__name__], device["id"], machine_key, root, leaf)
        phone.check()
    elif not enrolling and not setup and not (args.endpoint or args.serial or args.kdeconnect_device or args.kdeconnect_messages):
        # Default authentication route: signed messages over the enrolled phone's KDE Connect pairing.
        device = select_device(db, None, "authenticate")
        args.kdeconnect_messages = device["id"]
        args.phone_key_id = args.phone_key_id or device["phone_key_id"]
    elif not enrolling and not setup:
        for name in ("kdeconnect_messages", "kdeconnect_device"):
            if getattr(args, name):
                device = select_device(db, getattr(args, name), "authenticate")
                setattr(args, name, device["id"])
                args.phone_key_id = args.phone_key_id or device["phone_key_id"]
    if leaf is not None:
        pass  # Code pairing already connected the certified enrollment transport.
    elif getattr(args, "endpoint", None) or getattr(args, "kdeconnect_device", None) or getattr(args, "kdeconnect_messages", None):
        rows = db.execute("SELECT certificate FROM approved" + (" WHERE key_id=?" if args.phone_key_id else ""),
                          (args.phone_key_id,) if args.phone_key_id else ()).fetchall()
        if len(rows) != 1:
            raise ValueError("Select one already-approved phone with --phone-key-id")
        leaf = x509.load_der_x509_certificate(bytes(rows[0][0]))
        remote = None if setup else remote_config(db, digest(spki(leaf.public_key())))

        def make_primary():
            if args.kdeconnect_messages:
                return kdeconnect_transport()(sys.modules[__name__], args.kdeconnect_messages, machine_key, root, leaf)
            resolver = (lambda **options: kdeconnect_endpoint(args.kdeconnect_device, **options)) if args.kdeconnect_device else None
            return NetworkPhone(args.endpoint, machine_key, root, leaf, resolver)

        def make_remote():
            if remote is None:
                raise ValueError("Remote approvals are not set up for this phone (System Settings → Remote approvals)")
            return remote_module().RemotePhone(sys.modules[__name__], remote, machine_key, root, leaf)

        if args.remote_only:
            phone = make_remote()
            phone.check()
            emit("step", step="route", route="ntfy")
            say(f"Route: ntfy ({remote['server']})")
        elif remote is not None:
            # KDE Connect decides: the normal route when it sees the phone, ntfy otherwise.
            probe = None
            if args.kdeconnect_messages:
                # KDE Connect's "reachable" can be stale after Wi-Fi drops: confirm the phone answers.
                probe = lambda: lan_present(kdeconnect_addresses(args.kdeconnect_messages))
            phone = remote_module().RoutedPhone(make_primary, make_remote, probe=probe)
            phone.check()
            route = "ntfy" if phone.route == "remote" else "kdeconnect" if args.kdeconnect_messages else "network"
            emit("step", step="route", route=route)
            say(f"Route: {route}" + (f" ({remote['server']}): the phone is not reachable on the local network" if route == "ntfy" else ""))
        else:
            phone = None
            try:
                phone = make_primary()
                phone.check()
            except (OSError, ConnectionError, TimeoutError) as error:
                if phone is not None and hasattr(phone, "close"):
                    phone.close()
                if args.kdeconnect_messages:
                    raise
                raise ConnectionError("Phone not reachable over the network. In Navi, ☰ → Settings → Enable network "
                                      f"authentication, and keep the phone on the same network as this computer. ({error})") from error
    else:
        phone = Phone(args.serial)
    identity = phone.identity()
    public_der = unb64(identity["public_key_spki_base64"])
    public = serialization.load_der_public_key(public_der)
    key_id = digest(public_der)
    if identity["key_id_sha256"] != key_id:
        raise ValueError("Phone public-key ID mismatch.")
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ValueError("Phone key must be P-256.")
    if enrolling:
        leaf = leaf or certificate(public, root, machine_key, "Phone " + key_id[:32])
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    else:
        row = db.execute("SELECT certificate FROM approved WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise ValueError("This phone is not approved by this machine. Run enroll first.")
        leaf_der = bytes(row[0])
        leaf = x509.load_der_x509_certificate(leaf_der)
    validate_certificate(leaf, root)
    if spki(leaf.public_key()) != public_der:
        raise ValueError("Approved certificate belongs to another phone key.")

    machine_id = digest(spki(root.public_key()))
    request_id = secrets.token_hex(16)
    now = int(time.time() * 1000)
    payload = {"domain": DOMAIN, "kind": "enroll" if enrolling else "remote-setup" if setup else "authenticate",
               "request_id": request_id, "nonce": b64(secrets.token_bytes(32)),
               "machine_id": machine_id, "phone_key_id": key_id,
               "certificate_sha256": digest(leaf_der), "machine_name": socket.gethostname(),
               "operation": "Approve this phone for this computer" if enrolling
                   else "Allow remote approvals through " + urlsplit(args.server).netloc if setup else args.operation,
               "issued_at_ms": now, "expires_at_ms": now + TTL * 1000}
    local_user = pwd.getpwuid(os.getuid()).pw_name
    payload["context"] = {
        "application": "Phone Authenticator" if enrolling else args.application,
        "action_id": "enroll-phone" if enrolling else args.action_id,
        "command": "" if enrolling else args.requested_command,
        "requesting_user": local_user,
        "requesting_uid": os.getuid(),
        "target_user": local_user if enrolling else (args.target_user or local_user),
        "source": "manual-mvp",
        "icon_name": "dialog-password" if enrolling else args.icon_name,
        "icon_png_base64": "" if enrolling or args.icon_file is None else b64(args.icon_file.read_bytes()),
    }
    if setup:
        payload["context"].update(application="Navi remote approvals", action_id="remote-setup", command="",
                                  target_user=local_user, icon_name="network-wireless", icon_png_base64="")
        payload["remote_setup"] = {"server": args.server,
                                   "machine_ecdh_spki_b64": b64(spki(setup_key.public_key()))}
        if args.token:
            payload["remote_setup"]["token"] = args.token
    if not enrolling and not setup and args.context_file:
        if args.context_file.stat().st_size > 65536:
            raise ValueError("Desktop context is too large.")
        context = json.loads(args.context_file.read_bytes())
        if not isinstance(context, dict):
            raise ValueError("Desktop context must be an object.")
        payload["context"] = context
    if not enrolling and args.notification_only:
        payload["context"]["mode"] = "notification-only"
        payload["operation"] = "Verify phone approval for this desktop request"
    if not enrolling and args.desktop_request_id:
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.desktop_request_id):
            raise ValueError("Invalid desktop request UUID.")
        payload["context"]["desktop_request_id"] = args.desktop_request_id
    if isinstance(phone, remote_module().RoutedPhone) or args.remote_only:
        payload["remote"] = {"kind": "ntfy"}  # Navi may answer over ntfy, e.g. after Wi-Fi drops.
        if getattr(phone, "route", "remote") == "remote" and payload["context"].get("icon_png_base64"):
            # Over ntfy only the signed icon hash travels; Navi asks for the PNG if it lacks it.
            png = unb64(payload["context"]["icon_png_base64"])
            payload["context"]["icon_sha256"] = digest(png)
            payload["context"]["icon_png_base64"] = ""
            phone.set_icon(png)
    validate_context(payload["context"])
    if hasattr(phone, "transport"):
        payload["transport"] = phone.transport
    request = envelope(machine_key, payload)
    request["machine_certificate_b64"] = b64(root.public_bytes(serialization.Encoding.DER))
    request["phone_certificate_b64"] = b64(leaf_der)
    db.execute("INSERT INTO requests VALUES (?, ?, 'pending')", (request_id, encode(payload)))
    db.commit()
    deadline = time.monotonic() + TTL
    try:
        phone.write("request.json", request)
        phone.notify(request_id)
        say(f"Machine: {socket.gethostname()} · {machine_id}")
        say(f"Phone key: {key_id}")
        say(f"Request: {request_id}")
        say("Tap Approve on the phone and use your fingerprint. Waiting up to two minutes…")
        emit("step", step="awaiting-biometric", request_id=request_id, phone_key_id=key_id)
        while time.monotonic() < deadline:
            response = phone.read("response.json")
            if response and response.get("request_id") == request_id:
                if response.get("status") != "signed":
                    raise ValueError("Phone declined: " + str(response.get("message", "approval canceled")))
                raw = unb64(response["payload_b64"])
                if raw != encode(payload) or response["phone_certificate_b64"] != b64(leaf_der):
                    raise ValueError("Response does not match the outstanding challenge and certificate.")
                signature = unb64(response["signature_b64"])
                signed = raw
                if setup:
                    # The phone signs its fresh ECDH key together with this exact setup request.
                    phone_ecdh_der = unb64(response["phone_ecdh_spki_b64"])
                    phone_ecdh = serialization.load_der_public_key(phone_ecdh_der)
                    if not isinstance(phone_ecdh, ec.EllipticCurvePublicKey) or not isinstance(phone_ecdh.curve, ec.SECP256R1):
                        raise ValueError("The phone's remote key must be P-256.")
                    signed = raw + b"\n" + phone_ecdh_der
                leaf.public_key().verify(signature, signed, ec.ECDSA(hashes.SHA256()))
                validate_certificate(leaf, root)
                if time.monotonic() >= deadline:
                    raise ValueError("Approval arrived after the challenge expired.")
                # Consuming the challenge and approving its key are one transaction.
                with db:
                    changed = db.execute("UPDATE requests SET status='consumed' WHERE id=? AND status='pending'",
                                         (request_id,)).rowcount
                    if changed != 1:
                        raise ValueError("Challenge was already consumed or canceled.")
                    if setup:
                        derived = remote_module().derive(setup_key.exchange(ec.ECDH(), phone_ecdh), request_id)
                        db.execute("INSERT OR REPLACE INTO remote VALUES (?, ?, ?, ?, ?, ?, ?)",
                                   (key_id, args.server, args.token, derived["phone_topic"], derived["computer_topic"],
                                    derived["key"], int(time.time() * 1000)))
                    if enrolling:
                        db.execute("INSERT OR REPLACE INTO approved VALUES (?, ?)", (key_id, leaf_der))
                        db.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?)",
                                   (key_id, device["id"] if device else None,
                                    device["name"] if device else f"ADB {args.serial}", int(time.time() * 1000)))
                receipt_payload = {"domain": DOMAIN, "kind": "receipt", "request_id": request_id,
                                   "machine_id": machine_id, "phone_key_id": key_id,
                                   "response_sha256": digest(signature), "status": "approved",
                                   "verified_at_ms": int(time.time() * 1000)}
                receipt = envelope(machine_key, receipt_payload)
                atomic_write(STATE / "last-verification.json", encode({"request": request,
                             "response": response, "receipt": receipt}) + b"\n")
                phone.write("receipt.json", receipt)
                emit("step", step="receipt-sent")
                say("ENROLLED: this machine signed and approved the phone public key." if enrolling
                    else f"REMOTE APPROVALS ENABLED through {args.server}; used when KDE Connect can't see the phone." if setup
                    else "VERIFIED (notification-only): phone approval verified; desktop authentication is separate."
                    if args.notification_only else "AUTHENTICATED: approved phone certificate and fresh phone signature verified.")
                emit("done", result="enrolled" if enrolling else "remote-enabled" if setup
                     else "verified" if args.notification_only else "authenticated",
                     phone_key_id=key_id, device_id=device["id"] if device else None)
                return
            time.sleep(1)
        raise ValueError("Challenge expired without a signed approval.")
    finally:
        with db:
            canceled = db.execute("UPDATE requests SET status='canceled' WHERE id=? AND status='pending'", (request_id,)).rowcount
        if canceled:
            try:
                cancellation = envelope(machine_key, {"domain": DOMAIN, "kind": "cancel", "request_id": request_id,
                    "machine_id": machine_id, "phone_key_id": key_id, "request_sha256": digest(encode(payload))})
                phone.write("cancel.json", cancellation)
                phone.notify(request_id, canceled=True)
            except Exception as error:
                print(f"Cancellation delivery failed; phone request will expire: {error}", file=sys.stderr)
        if hasattr(phone, "close"):
            phone.close()


def default_state():
    # Checkouts created before 0.8 kept state beside the script; keep using it.
    legacy = Path(__file__).resolve().parent / ".state"
    if legacy.is_dir():
        return legacy
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "navi-auth"


def certificate_expiry(der):
    return int(x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp() * 1000)


# --- Installed root authority (read-only status, self-revocation) -------------
AUTHORIZE = Path("/usr/libexec/navi-auth/authorize")
EXEC_PROTOCOL = "navi-auth-exec/v1"


def authority_request(event, **fields):
    """One request/reply through the setuid helper; it derives this account from the kernel."""
    override = os.environ.get("NAVI_AUTH_AUTHORIZE")
    helper = Path(override) if override else AUTHORIZE
    try:
        info = helper.stat()
    except FileNotFoundError:
        return None, "The protected authority is not installed."
    if not override and (info.st_uid != 0 or not info.st_mode & 0o4000):
        return None, f"{helper} is not a root-owned setuid helper."
    request_id = str(uuid.uuid4())
    line = json.dumps(dict(protocol=EXEC_PROTOCOL, event=event, request_id=request_id, **fields)) + "\n"
    try:
        # Pipes (not a pty or socket): the helper requires private FIFOs.
        result = subprocess.run([str(helper)], input=line.encode(), capture_output=True, timeout=10, env={}, cwd="/")
    except subprocess.TimeoutExpired:
        return None, "The protected authority did not answer."
    reply = None
    for raw in result.stdout.splitlines():
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("protocol") == EXEC_PROTOCOL and value.get("request_id") == request_id:
            reply = value
    if reply is None or reply.get("event") == "error":
        detail = (reply or {}).get("message") or result.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no reply"]
        detail = detail if isinstance(detail, str) else detail[0]
        return None, "Protected authority: " + detail.split("authority-failed: ", 1)[-1][:300]
    return reply, None


KDESU = Path("/usr/libexec/kf6/kdesu")
KDESU_MARKER = "navi-auth-exec/v1"


def kdesu_navi_enabled(path=KDESU):
    """True when the installed kdesu carries the Navi patch, False when it does not, None if absent.

    The patch embeds its protocol name as a QStringLiteral (UTF-16LE); an unpatched kdesu never calls
    the authority, so administrator prompts silently fall back to the password dialog.
    """
    try:
        with open(path, "rb") as binary:
            data = binary.read(4 * 1024 * 1024)
    except OSError:
        return None
    return KDESU_MARKER.encode("utf-16-le") in data or KDESU_MARKER.encode() in data


def authority_status():
    reply, error = authority_request("status")
    if reply is None:
        emit("authority", available=False, error=error)
        say(error)
        return
    status = {name: reply.get(name) for name in ("configured", "valid", "reason", "account_matches", "enabled",
                                                 "machine_key_id", "phones") if name in reply}
    kdesu_navi = kdesu_navi_enabled()
    emit("authority", available=True, kdesu_navi=kdesu_navi, **status)
    if JSON_MODE:
        return
    if not status.get("configured"):
        print("Administrator prompts: not configured on this computer.")
    elif not status.get("valid"):
        print("Administrator prompts: configuration is invalid:", status.get("reason"))
    elif not status.get("account_matches"):
        print("Administrator prompts: configured for a different account.")
    else:
        print("Administrator prompts:", "enabled" if status.get("enabled") else "disabled")
        print("Authority machine ID:", status.get("machine_key_id"))
        for phone in status.get("phones", []):
            state = "enabled" if phone.get("enabled") else "revoked"
            remote = f" · remote: {phone['remote']}" if phone.get("remote") else ""
            print(f"  {phone['phone_key_id']} · {state} · {phone.get('transport')} · {phone.get('kdeconnect_device') or '-'}"
                  f" · certificate expires {(phone.get('certificate_expires') or '?')[:10]}{remote}")
        if kdesu_navi is False and any(phone.get("enabled") for phone in status.get("phones", [])):
            print(f"WARNING: {KDESU} is not the Navi-patched kdesu, so administrator prompts never reach the phone.")
            print("  A system update probably replaced kde-plasma/kdesu-gui; reinstall the Navi-patched build (see INSTALL).")


def show_status(root):
    """Read-only summary; it takes no session lock so it can run beside an enrollment."""
    machine_id = digest(spki(root.public_key())) if root is not None else None
    phones = []
    database = STATE / "approvals.sqlite3"
    if database.exists():
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            has_devices = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'").fetchone()
            query = ("SELECT a.key_id, a.certificate, d.kdeconnect_device, d.device_name, d.enrolled_at FROM approved a "
                     "LEFT JOIN devices d ON d.key_id = a.key_id" if has_devices else
                     "SELECT key_id, certificate, NULL, NULL, NULL FROM approved")
            remotes = remote_servers(db)
            for key_id, cert, device_id, name, enrolled_at in db.execute(query):
                phones.append(dict(phone_key_id=key_id, kdeconnect_device=device_id, device_name=name,
                                   enrolled_at_ms=enrolled_at, certificate_expires_at_ms=certificate_expiry(bytes(cert)),
                                   remote=remotes.get(key_id)))
    if JSON_MODE:
        emit("status", initialized=root is not None, machine_id=machine_id, state_dir=str(STATE), phones=phones)
        return
    if root is None:
        print("Not initialized. Run: host.py init")
        return
    print("Machine ID:", machine_id)
    print("Machine certificate:", STATE / "machine-cert.pem")
    for phone in phones:
        expires = datetime.fromtimestamp(phone["certificate_expires_at_ms"] / 1000, timezone.utc).date()
        label = f" · {phone['device_name']}" if phone["device_name"] else ""
        remote = f" · remote approvals: {phone['remote']}" if phone["remote"] else ""
        print(f"Approved phone: {phone['phone_key_id']}{label} · certificate expires {expires}{remote}")


def main():
    global STATE, JSON_MODE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=None, help="Private machine identity and approval database"
                        " (default: $XDG_STATE_HOME/navi-auth, or .state beside this script if present)")
    parser.add_argument("--json", action="store_true", help="Write one JSON event per line to stdout (for the settings UI)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create or inspect this machine's signing authority")
    sub.add_parser("status", help="Show machine identity and approved phone keys")
    sub.add_parser("devices", help="List paired KDE Connect devices and their enrollment")
    revoke = sub.add_parser("revoke", help="Remove a phone key's approval")
    revoke.add_argument("key_id")
    sub.add_parser("authority-status", help="Show which phones the installed root authority accepts for this account")
    authority_revoke = sub.add_parser("authority-revoke",
                                      help="Disable a KDE Connect device for administrator prompts (no password needed)")
    authority_revoke.add_argument("kdeconnect_device", metavar="DEVICE_ID")
    remote_setup = sub.add_parser("remote-setup", help="Let a phone approve over ntfy when KDE Connect can't see it")
    remote_setup.add_argument("--kdeconnect-device", dest="setup_device", metavar="ID_OR_NAME",
                              help="Enrolled phone (asks when several are enrolled)")
    remote_setup.add_argument("--server", default="https://ntfy.sh", help="ntfy server (default https://ntfy.sh)")
    remote_setup.add_argument("--token", help="ntfy access token, for a server with access control")
    remote_remove = sub.add_parser("remote-remove", help="Stop using ntfy for a phone")
    remote_remove.add_argument("--kdeconnect-device", dest="setup_device", metavar="ID_OR_NAME")
    for name in ("enroll", "authenticate"):
        command = sub.add_parser(name)
        transport = command.add_mutually_exclusive_group()
        transport.add_argument("--serial", help="Explicit Pixel or Nexus 6P ADB serial (debug APK fallback)")
        if name == "enroll":
            transport.add_argument("--kdeconnect-device", metavar="ID_OR_NAME",
                                   help="Pair with a code over KDE Connect (default; asks when several phones are available)")
        if name == "authenticate":
            transport.add_argument("--endpoint", help="Phone LAN IP:port, no debugging required")
            transport.add_argument("--kdeconnect-device", metavar="ID_OR_NAME", help="Resolve the paired phone's current LAN IP through KDE Connect")
            transport.add_argument("--kdeconnect-messages", metavar="ID_OR_NAME",
                                   help="Carry signed messages through the existing KDE Connect pairing (default)")
            command.add_argument("--phone-key-id", help="Already-approved phone key, required when more than one is approved")
            command.add_argument("--operation", default="Verify fingerprint authentication on this computer")
            command.add_argument("--application", default="Phone Authenticator")
            command.add_argument("--action-id", default="verify-identity", help="Requested authorization action")
            command.add_argument("--requested-command", default="", help="Command to display; never executed by this MVP")
            command.add_argument("--target-user", default="", help="Account the requested action would run as")
            command.add_argument("--icon-name", default="application-x-executable", help="Requester desktop icon name")
            command.add_argument("--icon-file", type=Path, help="Requester PNG thumbnail, at most 16 KiB and 256x256")
            command.add_argument("--context-file", type=Path, help="Desktop broker context JSON, signed verbatim after validation")
            command.add_argument("--desktop-request-id", help="Associated desktop dialog UUID")
            command.add_argument("--notification-only", action="store_true", help="Verify phone approval without authorizing desktop execution")
            command.add_argument("--remote-only", action="store_true", help="Send over ntfy even if KDE Connect can see the phone (test)")
    args = parser.parse_args()
    JSON_MODE = args.json
    if args.command == "remote-setup":
        args.server = remote_module().validate_server(args.server)
        if args.token is not None and not remote_module().TOKEN.fullmatch(args.token):
            raise ValueError("The ntfy access token may only contain letters, digits, '.', '_' and '-'.")
    STATE = (args.state_dir or default_state()).resolve()
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.stat().st_mode & 0o077:
        raise ValueError("State directory must be accessible only to its owner (chmod 700).")
    if args.command == "status":
        show_status(machine_identity()[1] if (STATE / "machine-key.pem").exists() else None)
        return
    if args.command == "authority-status":
        authority_status()
        return
    if args.command == "authority-revoke":
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", args.kdeconnect_device):
            raise ValueError("Expected a KDE Connect device ID.")
        reply, error = authority_request("revoke", kdeconnect_device=args.kdeconnect_device)
        if reply is None:
            raise ValueError(error)
        say("Disabled for administrator prompts.")
        emit("done", result="authority-revoked", kdeconnect_device=args.kdeconnect_device)
        return
    if args.command == "devices":
        database = STATE / "approvals.sqlite3"
        with sqlite3.connect(":memory:", uri=True) as db:
            db.execute("CREATE TABLE approved (key_id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE devices (key_id TEXT, kdeconnect_device TEXT, device_name TEXT, enrolled_at INTEGER)")
            db.execute("CREATE TABLE remote (key_id TEXT PRIMARY KEY, server TEXT, phone_topic TEXT, computer_topic TEXT)")
            if database.exists():
                db.execute("ATTACH DATABASE ? AS saved", (f"file:{database}?mode=ro",))
                db.execute("INSERT INTO approved SELECT key_id FROM saved.approved")
                if db.execute("SELECT 1 FROM saved.sqlite_master WHERE name='devices'").fetchone():
                    db.execute("INSERT INTO devices SELECT * FROM saved.devices")
                if db.execute("SELECT 1 FROM saved.sqlite_master WHERE name='remote'").fetchone():
                    db.execute("INSERT INTO remote SELECT key_id, server, phone_topic, computer_topic FROM saved.remote")
            devices = known_devices(db)
        if JSON_MODE:
            emit("devices", devices=devices)
        else:
            for device in devices:
                print(f"{device['id']}  {device_label(device)}")
            if not devices:
                print("No paired KDE Connect devices.")
        return
    if getattr(args, "operation", "") and (len(args.operation) > 160 or any(ord(c) < 32 for c in args.operation)):
        raise ValueError("Operation must be printable text of at most 160 characters.")
    for name, limit in (("application", 80), ("action_id", 160), ("requested_command", 512), ("target_user", 64), ("icon_name", 128)):
        value = getattr(args, name, "")
        if len(value) > limit or any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or 0x202a <= ord(c) <= 0x202e
                                     or 0x2066 <= ord(c) <= 0x2069 for c in value):
            raise ValueError(f"{name} must be plain display text of at most {limit} characters.")
    if getattr(args, "icon_file", None) is not None:
        icon = args.icon_file.read_bytes()
        if len(icon) < 24 or len(icon) > 16384 or icon[:8] != b"\x89PNG\r\n\x1a\n" or icon[12:16] != b"IHDR":
            raise ValueError("Requester icon must be a PNG thumbnail of at most 16 KiB.")
        width, height = struct.unpack(">II", icon[16:24])
        if not 1 <= width <= 256 or not 1 <= height <= 256:
            raise ValueError("Requester icon dimensions must not exceed 256x256.")
    with (STATE / "session.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another enrollment or authentication is already running for this account.") from None
        machine_key, root = machine_identity(create=args.command == "init")
        with sqlite3.connect(STATE / "approvals.sqlite3") as db:
            db.execute("CREATE TABLE IF NOT EXISTS approved (key_id TEXT PRIMARY KEY, certificate BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, payload BLOB NOT NULL, status TEXT NOT NULL)")
            # Display/route metadata only; trust is the approved table and its certificates.
            db.execute("CREATE TABLE IF NOT EXISTS devices (key_id TEXT PRIMARY KEY, kdeconnect_device TEXT, "
                       "device_name TEXT, enrolled_at INTEGER)")
            # Remote approvals (ntfy): server, derived topics and message key per approved phone.
            db.execute("CREATE TABLE IF NOT EXISTS remote (key_id TEXT PRIMARY KEY, server TEXT NOT NULL, token TEXT, "
                       "phone_topic TEXT NOT NULL, computer_topic TEXT NOT NULL, key BLOB NOT NULL, created_at INTEGER)")
            # A process restart cannot revive a previous challenge.
            db.execute("UPDATE requests SET status='canceled' WHERE status='pending'")
            db.commit()
            if args.command == "init":
                emit("done", result="initialized", machine_id=digest(spki(root.public_key())))
                if not JSON_MODE:
                    show_status(root)
            elif args.command == "revoke":
                if not re.fullmatch(r"[0-9a-f]{64}", args.key_id):
                    raise ValueError("Expected a SHA-256 phone key ID.")
                with db:
                    count = db.execute("DELETE FROM approved WHERE key_id=?", (args.key_id,)).rowcount
                    db.execute("DELETE FROM devices WHERE key_id=?", (args.key_id,))
                    db.execute("DELETE FROM remote WHERE key_id=?", (args.key_id,))
                say("Revoked." if count else "Key was not approved.")
                emit("done", result="revoked" if count else "not-approved", phone_key_id=args.key_id)
            elif args.command == "remote-remove":
                device = select_device(db, args.setup_device, "authenticate")
                with db:
                    count = db.execute("DELETE FROM remote WHERE key_id=?", (device["phone_key_id"],)).rowcount
                say(f"Remote approvals turned off for {device['name']}. Also turn them off in Navi → ☰ → Settings."
                    if count else f"Remote approvals were not set up for {device['name']}.")
                emit("done", result="remote-removed", device_id=device["id"], phone_key_id=device["phone_key_id"])
            else:
                approve(args, db, machine_key, root)


if __name__ == "__main__":
    def terminated(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminated)
    try:
        main()
    except KeyboardInterrupt:
        emit("error", message="Canceled.", canceled=True)
        print("Canceled.", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        emit("error", message=str(error))
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
