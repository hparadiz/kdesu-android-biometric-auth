#!/usr/bin/env python3
"""Render the bundled requester icons from icons/sources.json into icons/<sha256>.png + manifest.json.

    make icons          (or: tools/make_icons.py)   run inside the Plasma session

A developer command, like `make dictionary`: its output is committed, and builds and installs only
copy it. Every theme icon is rendered once per installed, selectable icon theme, with the same
algorithm kdesu uses for the PNG it sends (PhoneNotification::iconPngBase64): the icon at 128, 96,
64, 48 or 32 physical pixels, the first PNG of at most 16384 bytes. Icons that render identically
share one file. Navi shows a bundled icon whenever a request names its hash; anything else still
travels as before. Re-run after installing another icon theme.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "icons"
SOURCES = DIRECTORY / "sources.json"
MANIFEST = DIRECTORY / "manifest.json"
MAX_BYTES = 16384
SIZES = (128, 96, 64, 48, 32)
THEME_ROOTS = (Path("/usr/share/icons"), Path.home() / ".local/share/icons")


def installed_themes():
    """Selectable icon themes: not hidden, and with icon directories (cursor-only themes have none)."""
    themes = set()
    for base in THEME_ROOTS:
        for index in sorted(base.glob("*/index.theme")):
            values = {}
            for line in index.read_text(errors="replace").splitlines():
                if line.startswith("[") and values:
                    break  # Only the [Icon Theme] group
                if "=" in line:
                    key, value = line.split("=", 1)
                    values.setdefault(key.strip(), value.strip())
            if values.get("Hidden", "").lower() == "true" or not values.get("Directories"):
                continue
            themes.add(index.parent.name)
    return sorted(themes)


def render(icon):
    from PyQt6.QtCore import QBuffer, QIODevice, QSize
    for size in SIZES:
        pixmap = icon.pixmap(QSize(size, size), 1.0)
        if pixmap.isNull():
            return None
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        pixmap.toImage().save(buffer, "PNG")
        data = bytes(buffer.data())
        if len(data) <= MAX_BYTES:
            return data
    return None


def main(argv):
    if argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if not os.environ.get("WAYLAND_DISPLAY") and not os.environ.get("DISPLAY"):
        print("make_icons: run inside the desktop session (icons are rendered by the session's icon engine)", file=sys.stderr)
        return 1
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication
    app = QApplication(["make_icons"])  # noqa: F841 (kept alive for the icon engine)
    sources = json.loads(SOURCES.read_text())
    themes = installed_themes()
    if not themes:
        raise SystemExit("make_icons: no installed icon themes found")
    default = sources.get("default_theme", "breeze")
    if default not in themes:
        default = themes[0]
    rendered, icons, programs, paths, agents = {}, {}, {}, [], []
    for entry in sources["icons"]:
        ident = entry["id"]
        hashes = {}
        if "file" in entry:
            data = render(QIcon(str(DIRECTORY / entry["file"])))
            if data is None:
                raise SystemExit(f"make_icons: cannot render {entry['file']}")
            digest = hashlib.sha256(data).hexdigest()
            rendered[digest] = data
            hashes["*"] = digest
        else:
            for theme in themes:
                QIcon.setThemeName(theme)
                data = render(QIcon.fromTheme(entry["theme"]))
                if data is None:
                    print(f"note: {entry['theme']} is not available in {theme}")
                    continue
                digest = hashlib.sha256(data).hexdigest()
                rendered[digest] = data
                hashes[theme] = digest
        if not hashes:
            raise SystemExit(f"make_icons: {ident} rendered in no theme")
        icons[ident] = hashes
        for program in entry.get("programs", []):
            programs[program] = ident
        paths.extend([pattern, ident] for pattern in entry.get("paths", []))
        if entry.get("agent"):
            agents.append(ident)
    for digest, data in rendered.items():
        target = DIRECTORY / f"{digest}.png"
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
    removed = [path.name for path in DIRECTORY.glob("*.png") if path.stem not in rendered]
    for name in removed:
        (DIRECTORY / name).unlink()
    manifest = {"default_theme": default, "themes": themes, "icons": icons, "programs": programs,
                "paths": paths, "agents": agents}
    text = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    changed = not MANIFEST.exists() or MANIFEST.read_text() != text
    MANIFEST.write_text(text)
    print(f"themes: {', '.join(themes)} (default {default})")
    for ident, hashes in icons.items():
        cells = "  ".join(f"{theme}={digest[:12]}" for theme, digest in hashes.items())
        print(f"  {ident:26} {cells}")
    print(f"{len(rendered)} PNGs ({sum(map(len, rendered.values()))} bytes)"
          + (f"; removed {', '.join(removed)}" if removed else "") + ("; manifest updated" if changed else "; unchanged"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
