#!/usr/bin/env python3
"""Turn Navi's sudo approval on or off in /etc/pam.d/sudo, safely.

    sudo-pam status [--json]   anyone; reports whether the line is present and correct
    sudo-pam enable            root (System Settings runs it through pkexec)
    sudo-pam disable           root

Installed only when built with sudo approval (USE=sudo / make install ENABLE_SUDO=yes).
`enable` inserts exactly one marked line above the first auth rule; `disable` removes only
lines this tool recognises. The original file is backed up, the new one is written atomically
with the same owner and mode, and it is checked afterwards (restored from the backup on any
doubt). Files it does not recognise are left alone.
"""
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

PAM_FILE = Path("/etc/pam.d/sudo")
BACKUP = Path("/var/lib/navi-auth/pam-sudo.backup")
HELPER = Path(__file__).resolve().with_name("sudo-approve")
MARKER = "# navi-auth: phone approval for sudo in local Konsole/Kitty (System Settings or sudo-pam disable removes it)"
MAX_SIZE = 65536
# Any pam_exec rule that runs our helper, whatever its control or options (also hand-written ones).
OURS = re.compile(r"^\s*-?auth\s+(\S+|\[[^\]]*\])\s+pam_exec\.so\b(.*)\bsudo-approve\s*$")


def expected_line(helper=HELPER):
    return f"auth\tsufficient\tpam_exec.so quiet stdout seteuid {helper}"


def is_auth_rule(line):
    words = line.split()
    return bool(words) and (words[0] in ("auth", "-auth") or words[0].startswith("@include"))


def inspect(text, helper=HELPER):
    """State of the PAM file text: enabled | disabled | misplaced | outdated | unrecognized."""
    lines = text.splitlines()
    ours = [i for i, line in enumerate(lines) if OURS.match(line)]
    first_other = next((i for i, line in enumerate(lines) if is_auth_rule(line) and not OURS.match(line)), None)
    if first_other is None and not ours:
        return "unrecognized"
    if not ours:
        return "disabled"
    if len(ours) > 1 or any(lines[i].split() != expected_line(helper).split() for i in ours):
        return "outdated"  # e.g. hand-written without seteuid, or an old helper path
    if first_other is not None and ours[0] > first_other:
        return "misplaced"  # below the password rule: the password would be asked first
    return "enabled"


def without_ours(lines):
    return [line for line in lines if not OURS.match(line) and line.strip() != MARKER]


def enabled_text(text, helper=HELPER):
    lines = without_ours(text.splitlines())
    index = next((i for i, line in enumerate(lines) if is_auth_rule(line)), None)
    if index is None:
        raise ValueError("No auth rule found; refusing to change an unrecognized PAM file")
    lines[index:index] = [MARKER, expected_line(helper)]
    return "\n".join(lines) + "\n"


def disabled_text(text):
    return "\n".join(without_ours(text.splitlines())) + "\n"


def status(pam_file=PAM_FILE, helper=HELPER):
    result = {"file": str(pam_file), "line": expected_line(helper), "helper_installed": helper.exists()}
    try:
        result["state"] = inspect(pam_file.read_text(), helper)
    except OSError as error:
        result["state"] = "unreadable"
        result["error"] = str(error)
    return result


def read_protected(pam_file):
    info = pam_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > MAX_SIZE:
        raise ValueError(f"{pam_file} must be a root-owned regular file that only root can write")
    return pam_file.read_text(), info


def write_atomic(pam_file, text, info):
    descriptor, temporary = tempfile.mkstemp(prefix=".navi-auth-", dir=pam_file.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.replace(temporary, pam_file)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    directory = os.open(pam_file.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def change(enable, pam_file=PAM_FILE, helper=HELPER, backup=BACKUP):
    if os.geteuid() != 0:
        raise PermissionError("Run as root (System Settings asks for the administrator password)")
    if enable and not helper.exists():
        raise FileNotFoundError(f"{helper} is not installed (build with USE=sudo or ENABLE_SUDO=yes)")
    original, info = read_protected(pam_file)
    if inspect(original, helper) == "unrecognized":
        raise ValueError(f"{pam_file} has no auth rules; refusing to change it")
    updated = enabled_text(original, helper) if enable else disabled_text(original)
    if updated == original:
        return status(pam_file, helper)
    backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup.write_text(original)
    os.chmod(backup, 0o600)
    write_atomic(pam_file, updated, info)
    result = status(pam_file, helper)
    if result["state"] != ("enabled" if enable else "disabled"):
        write_atomic(pam_file, original, info)
        raise ValueError(f"Unexpected result ({result['state']}); {pam_file} was restored")
    return result


def main(argv):
    command = argv[0] if argv else ""
    as_json = "--json" in argv[1:]
    try:
        if command == "status":
            result = status()
        elif command in ("enable", "disable"):
            result = change(command == "enable")
        else:
            print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
            return 2
    except Exception as error:
        if as_json:
            print(json.dumps({"error": str(error)}))
        print(f"sudo-pam: {error}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(result))
    else:
        print(f"{result['file']}: phone approval for sudo is {result['state']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
