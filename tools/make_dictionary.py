#!/usr/bin/env python3
"""Build a new Navi DEFLATE preset dictionary from dictionaries/navi-deflate.sections.

    make dictionary            (or: tools/make_dictionary.py)
    tools/make_dictionary.py --check

This is a developer command. Its output is committed to the source tree; builds and installs only
copy the committed files and never run it. Each dictionary is identified on the wire by its SHA-256,
so a published dictionary must never change: a different result is written to the next free
dictionaries/navi-deflate-N.dict and dictionaries/DEFAULT is pointed at it. Older .dict files stay so
peers that still use them keep working.

--check exits non-zero if the sections no longer match the default dictionary (for tests and CI).
"""
import base64
import hashlib
import json
import os
import random
import re
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "dictionaries"
SECTIONS = DIRECTORY / "navi-deflate.sections"
DEFAULT = DIRECTORY / "DEFAULT"
NAME = re.compile(r"navi-deflate-([1-9][0-9]*)\.dict")
MAX_SIZE = 32768  # DEFLATE can only reference the last 32 KiB
WARN_SIZE = 4096  # Larger dictionaries add little for messages of this size


def build(text):
    """Dictionary bytes from the sections text."""
    parts, mode, entries = [], None, []

    def flush():
        if mode == "raw":
            parts.append("".join(entries))
        elif mode == "words":
            parts.append(" " + " ".join(entries) if entries else "")

    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = re.fullmatch(r"\[([A-Za-z0-9_-]+) (raw|words)\]", line.strip())
        if header:
            flush()
            mode, entries = header.group(2), []
            continue
        if mode is None:
            raise ValueError(f"line {number}: entry before the first [section]")
        if mode == "words":
            words = line.split()
            if " ".join(words) != line.strip():
                raise ValueError(f"line {number}: use single spaces between words")
            entries.append(line.strip())
        else:
            entries.append(line)
    flush()
    data = "".join(parts).encode("utf-8")
    if not data:
        raise ValueError("the dictionary is empty")
    if len(data) > MAX_SIZE:
        raise ValueError(f"the dictionary is {len(data)} bytes; DEFLATE uses at most {MAX_SIZE}")
    return data


def read_default():
    """(path, bytes) of the current default dictionary, or (None, b"") if there is none yet."""
    try:
        name, digest = DEFAULT.read_text().split()
    except FileNotFoundError:
        return None, b""
    path = DIRECTORY / name
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"{path} does not match the hash recorded in {DEFAULT}")
    return path, data


def sample_payloads():
    """Signed-request shaped payloads with commands typical for elevation (deterministic)."""
    commands = [
        "emerge -uDNav @world", "emerge --sync && eix-update",
        "cd /usr/src/linux && make olddefconfig && make -j$(nproc) && make modules_install && make install",
        "apt-get update && apt-get upgrade -y", "apt install -y nginx && ufw allow 'Nginx Full' && ufw enable",
        "docker compose -f /srv/app/docker-compose.yml pull && docker compose -f /srv/app/docker-compose.yml up -d",
        "curl -fsSL https://raw.githubusercontent.com/someone/project/main/install.sh -o /tmp/install.sh && sh /tmp/install.sh",
        "sysctl -w vm.swappiness=10 && echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf",
        "journalctl -u sddm -b --no-pager > /var/log/sddm-boot.log 2>&1",
        "echo 'Grüße aus München — 東京 ✓' > /etc/motd",
    ]
    rng = random.Random(7)
    hexed = lambda n: "".join(rng.choice("0123456789abcdef") for _ in range(n))
    payloads = []
    for size in (60, 250, 1000, 2000, 10240):
        command = ""
        while len(command) < size:
            command += rng.choice(commands) + "; "
        payload = dict(
            domain="in.akuj.fingerprint/v1", kind="authenticate", request_id=hexed(32), nonce=hexed(44),
            machine_id=hexed(64), phone_key_id=hexed(64), operation="Run this command as root", machine_name="workstation",
            context=dict(application="kdesu", action_id="org.kde.kdesu.run", command=command[:size], requesting_user="user",
                         requesting_uid=1000, target_user="root", source="kdesu", mode="execute",
                         icon_name="utilities-terminal", icon_png_base64="", icon_sha256=hexed(64)),
            execution=dict(shell="/bin/sh -c", uid=0, gid=0, cwd="/home/user",
                           environment={"DISPLAY": ":0", "XDG_RUNTIME_DIR": "/run/user/1000",
                                        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                                        "WAYLAND_DISPLAY": "wayland-0"}),
            issued_at_ms=1763395318000, expires_at_ms=1763395438000)
        payloads.append((size, json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()))
    return payloads


def deflated(data, dictionary):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=dictionary) if dictionary else zlib.compressobj(9, zlib.DEFLATED, -15)
    return len(compressor.compress(data) + compressor.flush())


def benchmark(old, new):
    print(f"{'command':>8} {'raw':>6} {'none':>6} {'old':>6} {'new':>6}   (compressed bytes)")
    for size, payload in sample_payloads():
        print(f"{size:>8} {len(payload):>6} {deflated(payload, None):>6} "
              f"{deflated(payload, old) if old else '-':>6} {deflated(payload, new):>6}")


def main(argv):
    if argv not in ([], ["--check"]):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    new = build(SECTIONS.read_text(encoding="utf-8"))
    current_path, current = read_default()
    if argv == ["--check"]:
        if new != current:
            print(f"{SECTIONS.name} differs from the default dictionary; run `make dictionary`", file=sys.stderr)
            return 1
        print(f"OK {current_path.name} {hashlib.sha256(current).hexdigest()}")
        return 0
    if new == current:
        print(f"unchanged: {current_path.name} ({len(current)} bytes, sha256 {hashlib.sha256(current).hexdigest()})")
        return 0
    numbers = [int(match.group(1)) for path in DIRECTORY.iterdir() if (match := NAME.fullmatch(path.name))]
    path = DIRECTORY / f"navi-deflate-{max(numbers, default=0) + 1}.dict"
    digest = hashlib.sha256(new).hexdigest()
    with open(path, "xb") as stream:  # never overwrite a published dictionary
        stream.write(new)
    temporary = DEFAULT.with_suffix(".tmp")
    temporary.write_text(f"{path.name} {digest}\n")
    os.replace(temporary, DEFAULT)
    print(f"wrote {path.relative_to(ROOT)} ({len(new)} bytes, sha256 {digest}); it is now the default")
    if len(new) > WARN_SIZE:
        print(f"note: larger than {WARN_SIZE} bytes; gains for small requests are usually marginal beyond this")
    benchmark(current, new)
    print(f"Commit {path.relative_to(ROOT)} and {DEFAULT.relative_to(ROOT)}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"make_dictionary: {error}", file=sys.stderr)
        sys.exit(1)
