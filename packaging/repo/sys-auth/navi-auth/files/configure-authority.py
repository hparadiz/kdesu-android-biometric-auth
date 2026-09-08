#!/usr/bin/env python3
"""Explicit administrator enrollment/revocation of the installed phone authority."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-state", type=Path)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--endpoint")
    parser.add_argument("--kdeconnect-device")
    parser.add_argument("--transport", choices=("kdeconnect-share", "lan"), default="kdeconnect-share")
    parser.add_argument("--phone-key-id")
    parser.add_argument("--machine-key-id")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run the installed configurator as administrator")
    os.umask(0o077)
    config_path = Path("/etc/navi-auth/config.json")
    if args.revoke:
        config = json.loads(config_path.read_text())
        config["enabled"] = False
        temporary = config_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(config))
        temporary.replace(config_path)
        print("Privileged phone approval revoked")
        return
    if not all((args.source_state, args.uid, args.phone_key_id, args.machine_key_id)):
        raise SystemExit("Explicit source, desktop UID, and both key IDs are required")
    if args.transport == "kdeconnect-share" and not args.kdeconnect_device:
        raise SystemExit("The paired KDE Connect device is required")
    if args.transport == "lan" and not args.endpoint:
        raise SystemExit("A phone LAN endpoint is required for direct TLS")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    source = args.source_state.resolve()
    root_bytes = (source / "machine-cert.pem").read_bytes()
    root = x509.load_pem_x509_certificate(root_bytes)
    def key_id(key):
        return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    if key_id(root.public_key()) != args.machine_key_id:
        raise SystemExit("The reviewed machine identity changed")
    private_bytes = (source / "machine-key.pem").read_bytes()
    private = serialization.load_pem_private_key(private_bytes, password=None)
    if key_id(private.public_key()) != args.machine_key_id:
        raise SystemExit("Machine key does not match its certificate")
    db = sqlite3.connect(f"file:{source / 'approvals.sqlite3'}?mode=ro", uri=True)
    row = db.execute("SELECT certificate FROM approved WHERE key_id=?", (args.phone_key_id,)).fetchone()
    if row is None or key_id(x509.load_der_x509_certificate(bytes(row[0])).public_key()) != args.phone_key_id:
        raise SystemExit("The reviewed phone approval is missing or changed")
    destination = Path("/var/lib/navi-auth")
    for path in (destination, config_path.parent):
        if path.is_symlink():
            raise SystemExit("Refusing a symlinked authority directory")
        path.mkdir(mode=0o700, exist_ok=True)
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
            raise SystemExit("Authority directories must be root-owned and private")
    if config_path.exists():
        current = json.loads(config_path.read_text())
        if current.get("phone_key_id") != args.phone_key_id or current.get("machine_key_id") != args.machine_key_id:
            raise SystemExit("Existing authority differs; refusing silent replacement")
    for name, data in (("machine-key.pem", private_bytes), ("machine-cert.pem", root_bytes)):
        output = destination / name
        temporary = output.with_suffix(".tmp")
        temporary.write_bytes(data)
        temporary.chmod(0o600)
        temporary.replace(output)
    config = dict(enabled=True, transport=args.transport, uid=args.uid, phone_key_id=args.phone_key_id,
                  machine_key_id=args.machine_key_id, phone_certificate_b64=base64.b64encode(bytes(row[0])).decode("ascii"))
    if args.endpoint:
        config["endpoint"] = args.endpoint
    if args.kdeconnect_device:
        config["kdeconnect_device"] = args.kdeconnect_device
    temporary = config_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config))
    temporary.chmod(0o600)
    temporary.replace(config_path)
    subprocess.run(["/usr/bin/python3.14", "-I", "/usr/libexec/navi-auth/rootauth.py", "--check"], check=True)
    print("Installed authority matches the approved phone and machine identities")


if __name__ == "__main__":
    main()
