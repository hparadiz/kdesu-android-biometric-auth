#!/usr/bin/env python3
"""Explicit administrator enrollment/revocation of installed phone authorities."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-state", type=Path)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--endpoint")
    parser.add_argument("--kdeconnect-device")
    parser.add_argument("--transport", choices=("kdeconnect-share", "lan"), default="lan")
    parser.add_argument("--phone-key-id")
    parser.add_argument("--machine-key-id")
    parser.add_argument("--add-phone", action="store_true", help="Explicitly add another approved phone; retain existing entries")
    parser.add_argument("--revoke", action="store_true", help="Revoke the selected phone, or every phone if no key is selected")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run the installed configurator as administrator")
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location("navi_authority", Path(__file__).with_name("rootauth.py"))
    authority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(authority)
    crypto = authority.crypto
    config_path = authority.CONFIG
    destination = authority.STATE
    for path in (destination, config_path.parent):
        authority.private_directory(path, 0o700)
    with authority.commit_guard():
        current = json.loads(authority.trusted_file(config_path, True), object_pairs_hook=authority.unique_object) if config_path.exists() else None
        if args.revoke:
            if current is None:
                raise SystemExit("No installed phone authority")
            entries = authority.phone_entries(current)
            matching = [entry for entry in entries if args.phone_key_id is None or entry["phone_key_id"] == args.phone_key_id]
            if not matching:
                raise SystemExit("The selected phone is not enrolled")
            for entry in matching:
                entry["enabled"] = False
            config = dict(enabled=any(entry.get("enabled", True) for entry in entries), uid=current["uid"],
                          machine_key_id=current["machine_key_id"], phones=entries)
            crypto.atomic_write(config_path, crypto.encode(config))
            print(f"Privileged approval revoked for {len(matching)} phone(s)")
            return
        if not all((args.source_state, args.uid, args.phone_key_id, args.machine_key_id)):
            raise SystemExit("Explicit source, desktop UID, and both key IDs are required")
        account = authority.pwd.getpwuid(args.uid)
        if account.pw_uid == 0:
            raise SystemExit("A non-root desktop account is required")
        if args.transport == "kdeconnect-share" and not args.kdeconnect_device:
            raise SystemExit("The paired KDE Connect device is required")
        if args.transport == "lan" and not (args.endpoint or args.kdeconnect_device):
            raise SystemExit("A paired KDE Connect device or explicit LAN endpoint is required")
        source = args.source_state.resolve()
        root_bytes = (source / "machine-cert.pem").read_bytes()
        private_bytes = (source / "machine-key.pem").read_bytes()
        root = crypto.x509.load_pem_x509_certificate(root_bytes)
        private = crypto.serialization.load_pem_private_key(private_bytes, password=None)
        def key_id(key):
            return hashlib.sha256(crypto.spki(key)).hexdigest()
        crypto.validate_certificate(root, root, ca=True)
        if key_id(root.public_key()) != args.machine_key_id or key_id(private.public_key()) != args.machine_key_id:
            raise SystemExit("The reviewed machine identity changed")
        with sqlite3.connect(f"file:{source / 'approvals.sqlite3'}?mode=ro", uri=True) as db:
            row = db.execute("SELECT certificate FROM approved WHERE key_id=?", (args.phone_key_id,)).fetchone()
        if row is None:
            raise SystemExit("The reviewed phone approval is missing")
        entry = dict(enabled=True, transport=args.transport, phone_key_id=args.phone_key_id,
                     phone_certificate_b64=base64.b64encode(bytes(row[0])).decode("ascii"))
        if args.endpoint:
            entry["endpoint"] = args.endpoint
        if args.kdeconnect_device:
            entry["kdeconnect_device"] = args.kdeconnect_device
        # Validate certificate, exact key pin and route before changing any trust.
        authority.PhoneAttempt(SimpleNamespace(root=root, key=private, account=account), entry)
        entries = []
        if current is not None:
            if current.get("machine_key_id") != args.machine_key_id or current.get("uid") != args.uid:
                raise SystemExit("Existing machine/account authority differs; refusing silent replacement")
            entries = authority.phone_entries(current)
            if not any(old["phone_key_id"] == args.phone_key_id for old in entries) and not args.add_phone:
                raise SystemExit("Adding a different phone requires explicit --add-phone")
        entries = [old for old in entries if old["phone_key_id"] != args.phone_key_id] + [entry]
        config = dict(enabled=True, uid=args.uid, machine_key_id=args.machine_key_id, phones=entries)
        authority.phone_entries(config)
        if len(crypto.encode(config)) > authority.MAX_MESSAGE:
            raise SystemExit("Phone configuration exceeds the authority limit")
        for name, data in (("machine-key.pem", private_bytes), ("machine-cert.pem", root_bytes)):
            output = destination / name
            if output.exists():
                authority.trusted_file(output, True)
            crypto.atomic_write(output, data)
            output.chmod(0o600)
        crypto.atomic_write(config_path, crypto.encode(config))
        config_path.chmod(0o600)
    print(f"Installed authority retains {len(entries)} enrolled phone(s); added or updated {args.phone_key_id}")


if __name__ == "__main__":
    main()
