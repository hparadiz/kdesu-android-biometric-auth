#!/usr/bin/env python3
"""Machine-issued phone credentials and biometric verification over signed LAN or ADB."""
import argparse
import base64
import fcntl
import hashlib
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
import ssl
import threading
from datetime import datetime, timedelta, timezone

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
        if not model.startswith("Pixel"):
            raise ValueError(f"Expected the selected Pixel; found {model!r}.")
        sdk = int(self.adb("shell", "getprop", "ro.build.version.sdk").decode().strip())
        if sdk < 30:
            raise ValueError("Android 11 or newer is required.")

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
    def __init__(self, endpoint, machine_key, root, leaf):
        import ipaddress
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("Expected a phone IP:port endpoint")
        address = ipaddress.ip_address(host.strip("[]"))
        if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError("Phone endpoint must be a private LAN address")
        validate_certificate(leaf, root)
        self.address = (str(address), int(port))
        self.key, self.root, self.leaf = machine_key, root, leaf
        self.machine_id = digest(spki(root.public_key()))
        self.phone_id = digest(spki(leaf.public_key()))
        self.request_id = None

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
        # Custom trust: the known biometric key certifies the transport key.
        # CERT_NONE suppresses Web PKI validation only; no RPC is sent until our
        # mandatory pinned-key verification below succeeds on this same socket.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        raw_socket = socket.create_connection(self.address, timeout=5)
        connection = None
        stream = None
        sockets = [raw_socket]
        def expire():
            try:
                sockets[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        watchdog = threading.Timer(10, expire)
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


def kdeconnect_endpoint(device_id, environment=None, account=None):
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
    def property_value(name):
        result = subprocess.run(["/usr/bin/qdbus6", "org.kde.kdeconnect", "/modules/kdeconnect/devices/" + device_id,
            "org.freedesktop.DBus.Properties.Get", "org.kde.kdeconnect.device", name],
            capture_output=True, timeout=5, check=True, **options)
        if len(result.stdout) > 4096:
            raise ValueError("Oversized KDE Connect reply")
        return result.stdout.decode().strip()
    if property_value("isPaired") != "true" or property_value("isReachable") != "true":
        raise ValueError("The paired Pixel is not reachable in KDE Connect")
    for candidate in property_value("reachableAddresses").splitlines():
        try:
            address = ipaddress.ip_address(candidate.strip())
        except ValueError:
            continue
        if address.version == 4 and address.is_private and not address.is_loopback and not address.is_unspecified:
            return f"{address}:39841"
    raise ValueError("KDE Connect has no private IPv4 LAN address for the phone")


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


def kdeconnect_transport():
    import importlib.util
    spec = importlib.util.spec_from_file_location("navi_kdeconnect_transport", Path(__file__).with_name("kdeconnect_transport.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.KdeConnectPhone


def approve(args, db, machine_key, root):
    if getattr(args, "endpoint", None) or getattr(args, "kdeconnect_device", None) or getattr(args, "kdeconnect_messages", None):
        rows = db.execute("SELECT certificate FROM approved" + (" WHERE key_id=?" if args.phone_key_id else ""),
                          (args.phone_key_id,) if args.phone_key_id else ()).fetchall()
        if len(rows) != 1:
            raise ValueError("Select one already-approved phone with --phone-key-id")
        leaf = x509.load_der_x509_certificate(bytes(rows[0][0]))
        if args.kdeconnect_messages:
            phone = kdeconnect_transport()(sys.modules[__name__], args.kdeconnect_messages, machine_key, root, leaf)
        else:
            endpoint = args.endpoint or kdeconnect_endpoint(args.kdeconnect_device)
            phone = NetworkPhone(endpoint, machine_key, root, leaf)
        phone.check()
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
    enrolling = args.command == "enroll"
    if enrolling:
        leaf = certificate(public, root, machine_key, "Phone " + key_id[:32])
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
    payload = {"domain": DOMAIN, "kind": "enroll" if enrolling else "authenticate",
               "request_id": request_id, "nonce": b64(secrets.token_bytes(32)),
               "machine_id": machine_id, "phone_key_id": key_id,
               "certificate_sha256": digest(leaf_der), "machine_name": socket.gethostname(),
               "operation": "Approve this phone for this computer" if enrolling else args.operation,
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
    if not enrolling and args.context_file:
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
        print(f"Machine: {socket.gethostname()} · {machine_id}", flush=True)
        print(f"Phone key: {key_id}", flush=True)
        print(f"Request: {request_id}", flush=True)
        print("Tap Approve on the phone and use your fingerprint. Waiting up to two minutes…", flush=True)
        while time.monotonic() < deadline:
            response = phone.read("response.json")
            if response and response.get("request_id") == request_id:
                if response.get("status") != "signed":
                    raise ValueError("Phone declined: " + str(response.get("message", "approval canceled")))
                raw = unb64(response["payload_b64"])
                if raw != encode(payload) or response["phone_certificate_b64"] != b64(leaf_der):
                    raise ValueError("Response does not match the outstanding challenge and certificate.")
                signature = unb64(response["signature_b64"])
                leaf.public_key().verify(signature, raw, ec.ECDSA(hashes.SHA256()))
                validate_certificate(leaf, root)
                if time.monotonic() >= deadline:
                    raise ValueError("Approval arrived after the challenge expired.")
                # Consuming the challenge and approving its key are one transaction.
                with db:
                    changed = db.execute("UPDATE requests SET status='consumed' WHERE id=? AND status='pending'",
                                         (request_id,)).rowcount
                    if changed != 1:
                        raise ValueError("Challenge was already consumed or canceled.")
                    if enrolling:
                        db.execute("INSERT OR REPLACE INTO approved VALUES (?, ?)", (key_id, leaf_der))
                receipt_payload = {"domain": DOMAIN, "kind": "receipt", "request_id": request_id,
                                   "machine_id": machine_id, "phone_key_id": key_id,
                                   "response_sha256": digest(signature), "status": "approved",
                                   "verified_at_ms": int(time.time() * 1000)}
                receipt = envelope(machine_key, receipt_payload)
                atomic_write(STATE / "last-verification.json", encode({"request": request,
                             "response": response, "receipt": receipt}) + b"\n")
                phone.write("receipt.json", receipt)
                print("ENROLLED: this machine signed and approved the phone public key." if enrolling
                      else "VERIFIED (notification-only): phone approval verified; desktop authentication is separate."
                      if args.notification_only else "AUTHENTICATED: approved phone certificate and fresh phone signature verified.", flush=True)
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


def main():
    global STATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=STATE, help="Private machine identity and approval database")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create or inspect this machine's signing authority")
    sub.add_parser("status", help="Show machine identity and approved phone keys")
    revoke = sub.add_parser("revoke", help="Remove a phone key's approval")
    revoke.add_argument("key_id")
    for name in ("enroll", "authenticate"):
        command = sub.add_parser(name)
        transport = command.add_mutually_exclusive_group(required=True)
        transport.add_argument("--serial", help="Explicit Pixel ADB serial (development only)")
        if name == "authenticate":
            transport.add_argument("--endpoint", help="Phone LAN IP:port, no debugging required")
            transport.add_argument("--kdeconnect-device", help="Resolve the paired phone's current LAN IP through KDE Connect")
            transport.add_argument("--kdeconnect-messages", help="Carry signed messages through the existing KDE Connect pairing")
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
    args = parser.parse_args()
    STATE = args.state_dir.resolve()
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.stat().st_mode & 0o077:
        raise ValueError("State directory must be accessible only to its owner (chmod 700).")
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
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        machine_key, root = machine_identity(create=args.command == "init")
        with sqlite3.connect(STATE / "approvals.sqlite3") as db:
            db.execute("CREATE TABLE IF NOT EXISTS approved (key_id TEXT PRIMARY KEY, certificate BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, payload BLOB NOT NULL, status TEXT NOT NULL)")
            # A process restart cannot revive a previous challenge.
            db.execute("UPDATE requests SET status='canceled' WHERE status='pending'")
            db.commit()
            if args.command in ("init", "status"):
                print("Machine ID:", digest(spki(root.public_key())))
                print("Machine certificate:", STATE / "machine-cert.pem")
                for row in db.execute("SELECT key_id FROM approved"):
                    print("Approved phone:", row[0])
            elif args.command == "revoke":
                if not re.fullmatch(r"[0-9a-f]{64}", args.key_id):
                    raise ValueError("Expected a SHA-256 phone key ID.")
                with db:
                    count = db.execute("DELETE FROM approved WHERE key_id=?", (args.key_id,)).rowcount
                print("Revoked." if count else "Key was not approved.")
            else:
                approve(args, db, machine_key, root)


if __name__ == "__main__":
    def terminated(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminated)
    try:
        main()
    except KeyboardInterrupt:
        print("Canceled.", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
