#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 PIXEL_ADB_SERIAL [release|debug]" >&2
    echo 'Use adb devices -l to identify your phone explicitly.' >&2
    exit 1
fi
serial="$1"
build_type="${2:-release}"
case "$build_type" in
    release|debug) ;;
    *) echo 'Expected release or debug build type.' >&2; exit 1 ;;
esac
apk="$project_dir/build/phone-authenticator-$build_type.apk"
[[ -f "$apk" ]] || { echo 'Run ./build.sh first.' >&2; exit 1; }
# Always address a specific device: a TV may also be attached to this ADB server.
model="$(adb -s "$serial" shell getprop ro.product.model | tr -d '\r')"
case "$model" in
    Pixel*) ;;
    *) echo "Refusing to install: expected a Pixel, found '$model'." >&2; exit 1 ;;
esac
adb -s "$serial" install -r "$apk"
adb -s "$serial" shell am start -n in.akuj.fingerprint/.MainActivity
