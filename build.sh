#!/usr/bin/env bash
# Offline APK build using the Android SDK directly; release is the default.
set -euo pipefail
umask 077
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"
build_type="${1:-release}"
if [[ $# -gt 1 || ( "$build_type" != release && "$build_type" != debug ) ]]; then
    echo "Usage: $0 [release|debug]" >&2
    exit 1
fi
resource_options=()
[[ "$build_type" != debug ]] || resource_options+=(--debug-mode)
sdk_dir="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$sdk_dir" ]]; then
    echo 'Set ANDROID_HOME to your Android SDK directory.' >&2
    exit 1
fi
tools_dir="$sdk_dir/build-tools/34.0.0"
android_jar="$sdk_dir/platforms/android-34/android.jar"
java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
javac_bin="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
jar_bin="${JAVA_HOME:+$JAVA_HOME/bin/}jar"
keytool_bin="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"
for required in "$android_jar" "$tools_dir/aapt2" "$tools_dir/zipalign" "$tools_dir/lib/d8.jar" "$tools_dir/lib/apksigner.jar"; do
    [[ -f "$required" ]] || { echo "Missing SDK component: $required" >&2; exit 1; }
done
"$java_bin" -version
out_dir="$project_dir/build"
# Preserve the existing app signing identity for in-place updates.
mkdir -p "$out_dir"
if [[ "$build_type" == release && ! -f "$out_dir/debug.keystore" ]]; then
    echo 'Release update requires the existing build/debug.keystore; refusing to generate a replacement signing identity.' >&2
    exit 1
fi
rm -rf -- "$out_dir/intermediates"
mkdir -p "$out_dir/intermediates"/{generated,classes,dex}
work_dir="$out_dir/intermediates"
"$tools_dir/aapt2" compile --dir app/src/main/res -o "$work_dir/resources.zip"
"$tools_dir/aapt2" link -I "$android_jar" --manifest app/src/main/AndroidManifest.xml \
    --java "$work_dir/generated" "${resource_options[@]}" -o "$work_dir/resources.apk" "$work_dir/resources.zip"
mapfile -d '' sources < <(find app/src/main/java "$work_dir/generated" -name '*.java' -print0)
# Parameter names also avoid old D8 crashing on unnamed synthetic parameters
# emitted by recent javac versions, even with --release 8.
"$javac_bin" --release 8 -parameters -Xlint:all,-options -cp "$android_jar" -d "$work_dir/classes" "${sources[@]}"
"$jar_bin" --create --file "$work_dir/classes.jar" -C "$work_dir/classes" .
"$java_bin" -cp "$tools_dir/lib/d8.jar" com.android.tools.r8.D8 --"$build_type" \
    --lib "$android_jar" --min-api 30 --output "$work_dir/dex" "$work_dir/classes.jar"
cp "$work_dir/resources.apk" "$work_dir/unsigned.apk"
"$jar_bin" --update --file "$work_dir/unsigned.apk" -C "$work_dir/dex" classes.dex
"$tools_dir/zipalign" -f 4 "$work_dir/unsigned.apk" "$work_dir/aligned.apk"
if [[ ! -f "$out_dir/debug.keystore" ]]; then
    "$keytool_bin" -genkeypair -keystore "$out_dir/debug.keystore" -storepass android \
        -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 \
        -validity 10000 -dname 'CN=Android Debug,O=Android,C=US' -noprompt
fi
apk="$out_dir/phone-authenticator-$build_type.apk"
"$java_bin" -jar "$tools_dir/lib/apksigner.jar" sign --ks "$out_dir/debug.keystore" \
    --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android \
    --out "$apk" "$work_dir/aligned.apk"
"$tools_dir/zipalign" -c 4 "$apk"
"$java_bin" -jar "$tools_dir/lib/apksigner.jar" verify --verbose "$apk"
badging="$("$tools_dir/aapt2" dump badging "$apk")"
if [[ "$build_type" == release && "$badging" == *application-debuggable* ]]; then
    echo 'Release verification failed: APK is debuggable.' >&2
    exit 1
fi
echo "Built $build_type: $apk"
