# Development

Start with [architecture](docs/ARCHITECTURE.md) and [security](SECURITY.md).
Treat changes to enrollment, signing, displayed command bytes, execution ownership
and revocation as changes to the authorization boundary.

## Source layout

- `app/`: Android framework-only Java application and resources.
- `build.sh`, `install.sh`: verified SDK build and explicit-device installer.
- `host.py`: unprivileged enrollment, authentication and revocation diagnostics.
- `authorize.c`, `rootauth.py`, `configure-authority.py`: protected desktop path.
- `kdeconnect_transport.py`: optional existing KDE Connect sharing transport.
- `packaging/repo/`: Gentoo navi-auth package with the deployed source snapshot.
- `packaging/kde-repo/`: KDE split ebuild and complete downstream patch, including
  the existing dialog/client test suites and preview fixture.
- `docs/`: setup, protocol, operation, audit and verification.

Root-level host files intentionally match the package copies. Update both when
making a runtime change; the build workflow checks their equality. Version future
package changes appropriately instead of silently treating them as the audited
0.7.0 deployment.

The private workstation installer, enrollment state, original signing key,
historical preview daemon and unfinished dedicated KDE Connect plugin are not
needed for this release and are not shipped. The existing KDE patch retains
historical notification-preview code/documentation; that path grants no execution
authority. Use the current architecture guide for the deployed flow.

## Build checks and existing tests

Follow [INSTALL.md](docs/INSTALL.md) for debug/release builds and a clean KDE patch
application. The existing QtTest suites run without a real phone or setuid fixture:

```sh
dbus-run-session -- env QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=generic \
  ctest --test-dir build/kde/out \
  -R '^kdesu_(dialog|phoneauth)_test$' --output-on-failure
```

They cover dialog behavior, helper-path checks, context, ready/commit ordering,
cancellation, malformed replies and postcommit uncertainty. They do not perform
an adversarial runtime audit of the actual root helper or Android hardware.

There is currently no Android/host automated test suite. Build/syntax checks and
manual device validation are documented separately; this publication does not
introduce tests or test infrastructure for those components.

## Android CI

GitHub Actions builds the explicit debug mode first to create a **disposable**
signer, then the non-debuggable release with the same temporary signer. It checks
shell/Python/C compilation, package-source consistency, APK alignment/signatures
and the release debuggable flag. It uploads only the release APK and its checksum,
never the keystore, intermediate directory or enrollment state.

The workflow uses a hosted Ubuntu runner and JDK 17, installs SDK platform and
build-tools 34, has read-only repository permissions and needs no signing secrets.
Each run has a different signing key. These artifacts cannot update your existing
app and are not a maintained release channel. Real enrollment and strong-biometric
hardware verification stay on a device. SDK/tool setup can be larger than the app
compilation; the framework-only APK itself is small.

Local builds remain supported without CI or network access after SDK setup.
For long-term release distribution, establish protected signing custody and a
deliberate compatible update process first. Do not upload a personal keystore to
make CI artifacts interchangeable.

## Changes and review

Keep protocol and execution changes small and document concrete before/after
behavior, validation, and known limitations. Preserve existing tests and per-file
licenses. Do not add hidden commands, approval caches, automatic postcommit retries,
global authentication hooks or new trusted channels as incidental refactors.

Before publishing, inspect the Git index for generated binaries, `.state`, keys,
private device identifiers and workstation paths. `.gitignore` is a backstop,
not a substitute for reviewing the actual staged content.
