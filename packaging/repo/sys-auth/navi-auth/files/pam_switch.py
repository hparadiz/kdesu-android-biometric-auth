#!/usr/bin/env python3
"""Turn Navi's optional phone approval on or off in PAM, safely.

    navi-pam status [SERVICE] [--json]   anyone; reports each built-in service's state
    navi-pam enable SERVICE              root (System Settings runs it through pkexec)
    navi-pam disable SERVICE             root

SERVICE is one of the approvals this installation was built with:
    sudo  sudo in local Konsole/Kitty terminals   (USE=sudo / ENABLE_SUDO=yes)
    sddm  the SDDM login screen                   (USE=login / ENABLE_LOGIN=yes)
    kde   the Plasma lock screen                  (USE=login / ENABLE_LOGIN=yes)

`enable` inserts exactly one marked line above the first auth rule of /etc/pam.d/SERVICE;
`disable` removes only lines this tool recognises. The original file is backed up, the new one is
written atomically with the same owner and mode and checked afterwards (restored on any doubt).
Files without auth rules are left alone.
"""
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAM_DIR = Path("/etc/pam.d")
BACKUP_DIR = Path("/var/lib/navi-auth")
MAX_SIZE = 65536
SERVICES = {
    "sudo": dict(helper="sudo-approve", options="quiet stdout seteuid",
                 marker="# navi-auth: phone approval for sudo in local Konsole/Kitty (System Settings or navi-pam disable sudo removes it)"),
    "sddm": dict(helper="login-approve", options="quiet stdout expose_authtok",
                 marker="# navi-auth: phone approval at the SDDM login screen, empty password + Enter (System Settings or navi-pam disable sddm removes it)"),
    "kde": dict(helper="login-approve", options="quiet stdout expose_authtok",
                marker="# navi-auth: phone approval at the Plasma lock screen, empty password + Enter (System Settings or navi-pam disable kde removes it)"),
}


def helper_path(service, directory=HERE):
    return directory / SERVICES[service]["helper"]


def available(directory=HERE):
    """Services whose helper was installed by this build."""
    return [service for service in SERVICES if helper_path(service, directory).exists()]


def expected_line(service, helper):
    return f"auth\tsufficient\tpam_exec.so {SERVICES[service]['options']} {helper}"


def ours(service):
    # Any pam_exec rule running this service's helper, whatever its control or options (also hand-written).
    return re.compile(r"^\s*-?auth\s+(\S+|\[[^\]]*\])\s+pam_exec\.so\b(.*)\b"
                      + re.escape(SERVICES[service]["helper"]) + r"\s*$")


def is_auth_rule(line):
    words = line.split()
    return bool(words) and (words[0] in ("auth", "-auth") or words[0].startswith("@include"))


def inspect(text, service, helper):
    """enabled | disabled | misplaced | outdated | unrecognized for one PAM file's text."""
    mine = ours(service)
    lines = text.splitlines()
    found = [i for i, line in enumerate(lines) if mine.match(line)]
    first_other = next((i for i, line in enumerate(lines) if is_auth_rule(line) and not mine.match(line)), None)
    if first_other is None and not found:
        return "unrecognized"
    if not found:
        return "disabled"
    if len(found) > 1 or any(lines[i].split() != expected_line(service, helper).split() for i in found):
        return "outdated"  # e.g. hand-written without seteuid, or an old helper path
    if first_other is not None and found[0] > first_other:
        return "misplaced"  # below the password rule: the password would be asked first
    return "enabled"


def without_ours(lines, service):
    mine, marker = ours(service), SERVICES[service]["marker"]
    return [line for line in lines if not mine.match(line) and line.strip() != marker]


def enabled_text(text, service, helper):
    lines = without_ours(text.splitlines(), service)
    index = next((i for i, line in enumerate(lines) if is_auth_rule(line)), None)
    if index is None:
        raise ValueError("No auth rule found; refusing to change an unrecognized PAM file")
    lines[index:index] = [SERVICES[service]["marker"], expected_line(service, helper)]
    return "\n".join(lines) + "\n"


def disabled_text(text, service):
    return "\n".join(without_ours(text.splitlines(), service)) + "\n"


def status(service, pam_dir=PAM_DIR, directory=HERE):
    helper = helper_path(service, directory)
    pam_file = pam_dir / service
    result = {"service": service, "file": str(pam_file), "line": expected_line(service, helper),
              "helper_installed": helper.exists()}
    try:
        result["state"] = inspect(pam_file.read_text(), service, helper)
    except FileNotFoundError:
        result["state"] = "unrecognized"  # e.g. SDDM not installed
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


def change(service, enable, pam_dir=PAM_DIR, directory=HERE, backup_dir=BACKUP_DIR):
    if service not in SERVICES:
        raise ValueError(f"Unknown service {service!r}")
    if os.geteuid() != 0:
        raise PermissionError("Run as root (System Settings asks for the administrator password)")
    helper = helper_path(service, directory)
    if enable and not helper.exists():
        raise FileNotFoundError(f"{helper} is not installed (this approval was not built in)")
    pam_file = pam_dir / service
    original, info = read_protected(pam_file)
    if inspect(original, service, helper) == "unrecognized":
        raise ValueError(f"{pam_file} has no auth rules; refusing to change it")
    updated = enabled_text(original, service, helper) if enable else disabled_text(original, service)
    if updated == original:
        return status(service, pam_dir, directory)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backup_dir / f"pam-{service}.backup"
    backup.write_text(original)
    os.chmod(backup, 0o600)
    write_atomic(pam_file, updated, info)
    result = status(service, pam_dir, directory)
    if result["state"] != ("enabled" if enable else "disabled"):
        write_atomic(pam_file, original, info)
        raise ValueError(f"Unexpected result ({result['state']}); {pam_file} was restored")
    return result


def main(argv):
    as_json = "--json" in argv
    args = [arg for arg in argv if arg != "--json"]
    command = args[0] if args else ""
    try:
        if command == "status" and len(args) <= 2:
            services = args[1:] or available()
            unknown = [service for service in services if service not in SERVICES]
            if unknown:
                raise ValueError(f"Unknown service {unknown[0]!r}")
            result = {service: status(service) for service in services}
        elif command in ("enable", "disable") and len(args) == 2:
            result = {args[1]: change(args[1], command == "enable")}
        else:
            print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
            return 2
    except Exception as error:
        if as_json:
            print(json.dumps({"error": str(error)}))
        print(f"navi-pam: {error}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(result))
    else:
        for service, value in result.items():
            print(f"{value['file']}: phone approval is {value['state']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
