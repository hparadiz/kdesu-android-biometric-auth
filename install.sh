#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 PHONE_ADB_SERIAL [release|debug]" >&2
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
    Pixel*|"Nexus 6P") ;;
    *) echo "Refusing to install: expected a Pixel or Nexus 6P, found '$model'." >&2; exit 1 ;;
esac
sdk="$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')"
if [[ ! "$sdk" =~ ^[0-9]+$ ]] || (( sdk < 28 )); then
    echo "Refusing to install: Android 9 (API 28) or newer is required; found API '$sdk'." >&2
    exit 1
fi
adb -s "$serial" install -r "$apk"
launch="$(adb -s "$serial" shell am start -W -n in.akuj.fingerprint/.MainActivity)"
printf '%s\n' "$launch"
if [[ "$launch" == *"Error:"* || "$launch" == *"Error type"* ]]; then
    echo 'Installed, but launch failed. Unlock the phone once after boot, then open Navi Authenticator.' >&2
    exit 1
fi
