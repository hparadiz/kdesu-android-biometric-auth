# Build, enroll and install

## Supported baseline

- Android 9/API 28 or newer, enrolled strong biometrics and a hardware-backed
  Keystore signing implementation. Tested on Pixel 9 Pro (Android 16/API 36) and
  Nexus 6P (Android 9/API 28 ROM). Stock Nexus firmware older than Android 9 is
  unsupported. **ADB enrollment and installation accept Pixel or Nexus 6P.**
  Other manufacturers are unverified and need the model restriction reviewed;
  installing an APK manually does not remove the enrollment helper restriction.
- Linux with Python and `cryptography` **42+** for the manual host CLI. The
  installed desktop launcher/configurator are currently pinned to
  **`/usr/bin/python3.14`**. Use distro packages for the protected interpreter and
  its modules, not a user virtualenv.
- Android SDK **platforms;android-34**, **build-tools;34.0.0**, platform-tools/ADB,
  Bash and JDK 17+. No third-party Android runtime dependencies.
- Desktop: KDE CLI Tools 6.7.2, Qt 6.10+ (Gentoo ebuild: 6.10.1+), KDE Frameworks
  and ECM 6.26+, CMake, a C/C++20 toolchain, Qt GUI private headers and the KDE
  dependencies listed in the ebuild. The installed baseline is Gentoo; this is
  not a universal install script for older KDE distributions.

## 1. Build the APK

```sh
git clone https://github.com/hparadiz/kdesu-android-biometric-auth.git
cd kdesu-android-biometric-auth
export ANDROID_HOME="$HOME/Android/Sdk"
# Set JAVA_HOME to an installed JDK if Java is not already on PATH.
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
  'platforms;android-34' 'build-tools;34.0.0' 'platform-tools'
./build.sh release --new-key   # first installation only; later: ./build.sh release
```

SDK installation requires accepting Google's SDK licenses; the build itself is
offline once these components are installed. See the official
[sdkmanager documentation](https://developer.android.com/tools/sdkmanager).

`--new-key` creates `build/debug.keystore` and refuses to run if one exists.
**Keep this private key and back it up securely.** The historical script uses the
standard development alias/password, so filesystem protection is what protects
that file. Do not commit it or put it in CI artifacts. Debug and release builds
use this same key to preserve updates; its name does not control the APK's
debuggable flag. A separate production signing workflow and protected
signing-key custody are still needed for wider deployment.

Install the APK with `./install.sh SERIAL release` over USB/wireless debugging, or
copy it to the phone and install it there. ADB is not needed after installation.

## 2. Enroll the phone

### With a pairing code (release build)

1. Pair the phone with this computer in KDE Connect and leave file sharing enabled.
2. In Navi, tap **Set up KDE Connect** and choose **Navi Authenticator** as KDE
   Connect's destination folder. Open Navi once so it prepares its signing key.
3. On the computer, either open **System Settings → Security & Privacy → Navi
   Authenticator**, press **Create Identity** once and then **Enroll** next to the
   phone, or use the terminal:

   ```sh
   python3 host.py init
   python3 host.py enroll                         # asks when several phones are available
   python3 host.py enroll --kdeconnect-device "Pixel 9 Pro"   # or select by name / ID
   ```

4. The computer shows a code such as `K7QM-3XPA`. Navi shows **Pair with a
   computer** with the computer's name and fingerprint; check them, type the code
   and tap **Confirm code**. KDE Connect returns the phone's key to the computer.

   **No code box?** Then KDE Connect saved the offer to the phone's Downloads
   (step 2 was skipped). Either tap KDE Connect's "file received" notification and
   open it with **Navi pairing offer**, or in Navi tap **Pair a computer… → Open
   pairing offer…** and choose the `navi-auth-enroll-offer-….json` file the
   computer names. Only pairing offers are accepted this way, and they still need
   the code. Navi shows the same instructions until a computer is paired.
5. Navi then shows the enrollment request. Tap **Approve enrollment** and complete
   the biometric prompt. The terminal prints `ENROLLED`; System Settings marks the
   phone **Enrolled**. Press **Send Test** (or run `python3 host.py authenticate`)
   to verify an approval.

`host.py devices` lists the paired KDE Connect devices and their enrollment, and
`host.py status` shows the machine and phone key IDs. State lives in
`$XDG_STATE_HOME/navi-auth` (normally `~/.local/state/navi-auth`); an existing
`.state` directory beside `host.py` keeps being used. The code expires after ten
minutes, and five wrong entries discard it.

### Android 9–10 without ADB (e.g. Nexus 6P)

KDE Connect on these versions saves received files to `Download/`. In Navi tap
**Read computer messages from Downloads** and allow storage access (only
requested on Android 9–10). Keep Navi open during enrollment: it checks
`Download/` when it opens, regains focus and every few seconds while visible,
handles recent `navi-auth-*.json` files exactly like KDE Connect deliveries, and
deletes them. Enroll as above. Afterwards configure kdesu with the LAN transport
(`--transport lan --kdeconnect-device …`), which does not depend on files.

### ADB fallback (debug build, Android 9 such as the Nexus 6P)

Android 9 cannot receive KDE Connect messages in Navi, so it keeps the original
bootstrap. Use a trusted computer and authorize USB debugging. Android 11+ also
supports Wireless debugging with **Pair device with pairing code**:

```sh
./build.sh debug
adb pair PHONE_IP:PAIRING_PORT
adb connect PHONE_IP:CONNECTION_PORT
adb devices -l
./install.sh PHONE_IP:CONNECTION_PORT debug
python3 host.py init
python3 host.py enroll --serial PHONE_IP:CONNECTION_PORT
```

Use the USB serial instead if connected over USB, including on Android 9. The pairing port and connection
port are different. Always select a device explicitly. On the phone, review the
computer enrollment request, tap Approve and complete the biometric operation.
The host must print `ENROLLED`. Save the IDs from `python3 host.py status`.

This bootstrap uses ADB `run-as` to access the debug app's private mailbox. New
enrollment into a non-debuggable release without a matching pairing code is
**rejected by the request validator**, including requests to replace an existing
pairing. Existing enrollment does not need to be repeated for compatible updates.

### Network authentication

On the phone, tap **Enable network authentication**, approve its one-time transport
key binding, and complete [background setup](BACKGROUND.md). Wait for **Ready on
your network · port 39841**.

## 3. Update in place to release

```sh
./build.sh release
./install.sh PHONE_IP:CONNECTION_PORT release
python3 host.py authenticate --endpoint PHONE_IP:39841 \
  --operation 'Verify the release installation'
```

Approve on the phone. The host must print `AUTHENTICATED` and exit 0. Release is
also the default for `build.sh` and `install.sh`; it refuses to generate a new
signing identity when the keystore is missing. Keep the same signing key across
updates. Do not uninstall, clear storage or reset phone keys as part of an update.

Verify the installed release blocks development mailbox access:

```sh
adb -s PHONE_IP:CONNECTION_PORT shell run-as in.akuj.fingerprint id
```

Expected: `package not debuggable`. Disable/revoke development debugging access
when it is no longer needed. Direct Wi-Fi authentication continues without ADB.
See [SECURITY.md](../SECURITY.md) for the remaining app-update signing risk.

For a stationary rear-sensor phone, turn on **Desk reader mode** and leave Navi
open and unlocked. Incoming authentication requests open the biometric prompt
automatically; the screen stays awake while Navi is visible. Canceled requests
do not reopen themselves. This does not start the app from the background or
unlock the device. New enrollment and network setup still require their normal
taps. Android 9 uses direct Wi-Fi; the optional KDE Connect folder bridge requires
Android 10+ and is hidden on Android 9.

## 4. Build the KDE integration without installing

The repository carries the complete downstream patch, including existing tests,
rather than a copy of the whole KDE source tree. Starting at this repository root:

```sh
repo_dir="$PWD"
mkdir -p build/kde
curl --fail --location --output build/kde/kde-cli-tools-6.7.2.tar.xz \
  https://download.kde.org/stable/plasma/6.7.2/kde-cli-tools-6.7.2.tar.xz
printf '%s  %s\n' \
  f76a520bb2f89a69cf1785885dd58185ff952f484893430928895af277ccc37b \
  build/kde/kde-cli-tools-6.7.2.tar.xz | sha256sum --check
tar -xf build/kde/kde-cli-tools-6.7.2.tar.xz -C build/kde
cd build/kde/kde-cli-tools-6.7.2
patch -p1 < "$repo_dir/packaging/kde-repo/kde-plasma/kdesu-gui/files/kdesu-gui-6.1.80-build-only-kdesu.patch"
patch -p1 < "$repo_dir/packaging/kde-repo/kde-plasma/kdesu-gui/files/kdesu-gui-6.7.2-r2-navi.patch"
patch -p1 < "$repo_dir/packaging/kde-repo/kde-plasma/kdesu-gui/files/kdesu-gui-6.7.2-r3-retry.patch"
cmake -S . -B ../out -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_DOC=OFF -DBUILD_TESTING=ON
cmake --build ../out --parallel 4
dbus-run-session -- env QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=generic \
  ctest --test-dir ../out \
  -R '^kdesu_(dialog|phoneauth)_test$' --output-on-failure
cd "$repo_dir"
```

The first patch restricts the build to kdesu. The second adds the phone integration
and dialog changes. QtTest must be present; check that CMake actually enables the
two tests. Building previews/tests does not install or grant root privileges.
The isolated D-Bus session avoids contacting the current desktop during tests.
The archive digest identifies the upstream input used here; it is not a substitute
for your own upstream provenance verification.

## 5. Install desktop packages on Gentoo

This step changes the system and installs a **setuid root helper**. Review the
source and Portage plan before proceeding. Use an existing administrator route
for initial installation; the new phone authority cannot bootstrap its own trust.
Keep a working administrative recovery method.

The following are commands for an administrator shell. Replace `REVIEWED_COMMIT`
with the full commit you inspected. A protected checkout prevents the desktop
account from replacing packaging while Portage reads it.

```sh
git clone https://github.com/hparadiz/kdesu-android-biometric-auth.git \
  /var/db/repos/kdesu-biometric-source
git -C /var/db/repos/kdesu-biometric-source checkout --detach REVIEWED_COMMIT
install -d -m 0755 /etc/portage/repos.conf
cat > /etc/portage/repos.conf/navi-auth-local.conf <<'EOF'
[navi-auth-local]
location = /var/db/repos/kdesu-biometric-source/packaging/repo
masters = gentoo
auto-sync = no
EOF
cat > /etc/portage/repos.conf/navi-kde-local.conf <<'EOF'
[navi-kde-local]
location = /var/db/repos/kdesu-biometric-source/packaging/kde-repo
masters = gentoo
auto-sync = no
EOF
ebuild /var/db/repos/kdesu-biometric-source/packaging/repo/sys-auth/navi-auth/navi-auth-0.8.0.ebuild manifest
ebuild /var/db/repos/kdesu-biometric-source/packaging/repo/kde-misc/navi-auth-kcm/navi-auth-kcm-0.8.0.ebuild manifest
emerge --pretend --verbose --oneshot \
  '=sys-auth/navi-auth-0.8.0::navi-auth-local' \
  '=kde-misc/navi-auth-kcm-0.8.0::navi-auth-local' \
  '=kde-plasma/kdesu-gui-6.7.2-r3::navi-kde-local'
```

Resolve any package/keyword/USE differences deliberately for your system; the
reference machine's dependency availability is not universal. The current navi-auth
ebuild includes KDE Connect, D-Bus and PyGObject dependencies even if you choose LAN.
After accepting the exact plan:

```sh
emerge --ask=n --oneshot --usepkg=n --getbinpkg=n --autounmask=n \
  '=sys-auth/navi-auth-0.8.0::navi-auth-local' \
  '=kde-misc/navi-auth-kcm-0.8.0::navi-auth-local' \
  '=kde-plasma/kdesu-gui-6.7.2-r3::navi-kde-local'
```

For existing phone-capable kdesu installations, run authorized administrative
commands through `kdesu -n --noignorebutton -c '...'`, capturing the child's log
and completion status. Its phone path has no interactive child stdin; do not use
`emerge --ask` there. This guide does not ship a self-elevating installer.

Other distributions need native packaging for the fixed interpreter, helper
permissions and KDE dependencies. Do not install a setuid helper from a
user-writable build directory or point it at user-writable Python code.

## 6. Configure the protected enrollment

In the administrator shell, substitute the enrolled user's path, numeric UID,
paired KDE Connect device ID and both full key IDs reported by `host.py status`
(System Settings shows the complete command under **Use for Administrator
Prompts…**). Use the state directory printed by `host.py --json status`; older
checkouts keep `.state` beside `host.py`:

```sh
/usr/bin/python3.14 -I /usr/libexec/navi-auth/configure-authority.py \
  --source-state /home/alice/.local/state/navi-auth \
  --uid 1000 --transport lan --kdeconnect-device PAIRED_DEVICE_ID \
  --phone-key-id PHONE_KEY_SHA256 --machine-key-id MACHINE_KEY_SHA256
/usr/bin/python3.14 -I /usr/libexec/navi-auth/rootauth.py --check
stat -c '%U:%G %a %n' /usr/libexec/navi-auth/authorize \
  /etc/navi-auth /var/lib/navi-auth
```

Expected ownership: root:root; helper 4755; private trust directories 700. The
configurator checks the selected identities and refuses a silent replacement of
an existing different authority. Configuration copies the machine private key;
the original development copy remains sensitive and is not automatically removed.
Find the paired device ID with `kdeconnect-cli --list-devices`. The LAN route
resolves its current address for every request. On a connection failure it asks
KDE Connect for one UDP/mDNS discovery refresh and reconnects to the running
Android app, still verifying the enrolled biometric key. No phone IP is stored
when a device ID is configured. An explicit `--endpoint PHONE_IP:39841` remains
available for installations without KDE Connect discovery.

### Add another enrolled phone

Enroll the additional phone with the **same machine identity/state directory**
using the pairing code (or the ADB fallback), then enable its network connection.
In System Settings, **Use for Administrator Prompts…** in a phone's menu shows the
exact configurator command below for that phone. Select the intended certificate with `--phone-key-id` when using the
host CLI after multiple phones have been enrolled.

From the administrator shell, add the reviewed phone without replacing the others:

```sh
/usr/bin/python3.14 -I /usr/libexec/navi-auth/configure-authority.py \
  --source-state /home/alice/.local/state/navi-auth \
  --uid 1000 --transport lan --endpoint SECOND_PHONE_IP:39841 \
  --phone-key-id SECOND_PHONE_KEY_SHA256 --machine-key-id MACHINE_KEY_SHA256 \
  --add-phone
/usr/bin/python3.14 -I /usr/libexec/navi-auth/rootauth.py --check
```

Use `--kdeconnect-device SECOND_DEVICE_ID` instead of `--endpoint` for discovery.
The protected registry holds up to 32 phones, each with its own certificate and
route. Existing single-phone configuration remains readable and migrates when
updated. The desktop sends all enabled phones independent requests for the same
command; the first verified approval wins, and other phones receive withdrawals.

To disable one phone while retaining the others:

```sh
/usr/bin/python3.14 -I /usr/libexec/navi-auth/configure-authority.py \
  --revoke --phone-key-id PHONE_KEY_SHA256
```

## 7. Verify kdesu and operate it

From the desktop user, choose a new output name for each run:

```sh
result="/run/navi-auth/check-$(date +%s)-$$.uid"
kdesu -n --noignorebutton -c "/usr/bin/id -u > '$result'"
cat "$result"
stat -c '%U:%G %a %n' "$result"
```

Approve the visible command on the phone. Expect `0` in a root-owned file. `-n`
disables cached-password use; check that the phone path actually completes.
kdesu's exit code confirms launch only; independently inspect the child result.
Do not add `-t` or `-d`: terminal or hidden-command requests are ineligible.

For commands that invoke scripts, approval of a path does not freeze its contents.
Execute the same verified bytes or a protected snapshot. Hashing and subsequently
reopening a writable path leaves a race. Keep commands within 512 characters and
preserve the exact command for review; do not hide large payloads in encodings.

## Revocation, removal and recovery

To disable protected phone execution, an administrator runs:

```sh
/usr/bin/python3.14 -I /usr/libexec/navi-auth/configure-authority.py --revoke
```

This prevents new requests and rejects a configuration change observed before
commit. It cannot undo an already committed command. `host.py revoke PHONE_KEY`
only affects development state. Phone key reset affects all paired computers.

The configured desktop account can also disable its own phone without a password,
and can check what the installed authority accepts for it:

```sh
python3 host.py authority-status                 # read-only; uses the installed setuid helper
python3 host.py authority-revoke KDECONNECT_DEVICE_ID
```

System Settings → Navi Authenticator shows an **Administrator prompts** switch on
each enrolled phone. Turning it on asks for the administrator password (polkit action
`in.akuj.navi-auth.configure-authority`, which runs `/usr/libexec/navi-auth/configure`,
a fixed wrapper around the configurator above with `--transport kdeconnect-share
--add-phone`). Turning it off, or **Remove Enrollment**, disables the phone without a
password.

Remove `sys-auth/navi-auth` with your package manager to remove its executable;
review retained root-private state separately. Restore the distribution's kdesu
package if removing the GUI patch. No desktop daemon needs disabling. Never
delete signing keys or trust backups casually: losing them changes recovery and
update options. Certificate expiry or invalidated Android biometric keys requires
explicit renewed enrollment and a reviewed protected configuration update.
