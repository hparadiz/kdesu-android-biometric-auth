# Verification record

## Live deployment evidence — 2026-09-08

Reference environment: Gentoo Linux, KDE kdesu-gui 6.7.2-r2, navi-auth 0.7.0,
Pixel 9 Pro with Android 16/API 36. Results below are observations from that
deployment, not claims that every supported device behaves identically.

- Android 0.8.1/code10 was installed in place over the enrolled app. Package
  signing identity was preserved; no uninstall, reset or new enrollment occurred.
- APK and installed-package checks showed a non-debuggable release. Android
  rejected `run-as` access to the package.
- The foreground connection service was running after the update, before an app
  activity was explicitly opened. Background permissions were reported ready.
- Direct LAN TLS identity verification matched the existing approved phone key.
- A fresh 0.8.1 biometric CLI request passed certificate/signature verification,
  returned exit 0 and transitioned to consumed. An earlier request expired without
  approval; its misleading `Invalid network frame` error is documented.
- Separately, with Android 0.8.0, the installed kdesu phone flow launched a root
  command: a fresh file in a root-protected directory contained UID `0`, was owned
  by root, and kdesu returned 0. This is the observed root-execution result; the
  later 0.8.1 retry was authentication-only.

Private device addresses, key identifiers, request IDs, enrollment state and
authorization receipts are deliberately not distributed as example credentials.

## Publication build

A clean publication checkout was assembled from Android 0.8.1 sources and the
deployed desktop 0.7.0 package snapshot. With SDK platform/build-tools 34 and
JDK 25, both explicit debug and release builds completed using a new local
throwaway signer. APK alignment and v3 signature checks passed. Debug badging
was enabled only for the debug build; the release had no debuggable flag and was
71,312 bytes. This throwaway APK was not installed over the enrolled phone.

Shell syntax, Python compilation, native helper compilation with warnings as
errors, and equality between root-level desktop sources and package copies passed.
Both KDE patches applied to the clean upstream 6.7.2 archive, and the patched
desktop compiled. The existing suites passed: **40 dialog checks and 32 phone
client checks, zero failures/skips**. CTest reported 2/2 suites passed in 6.38
seconds using an isolated D-Bus session and the offscreen Qt platform. An initial
sandboxed GUI startup stalled and was stopped; the isolated unprivileged run
completed. No real phone or root helper was used by these fixture tests.

The GitHub workflow builds with JDK 17 and its own temporary signer. Its run
results are available under [Actions](https://github.com/hparadiz/kdesu-android-biometric-auth/actions).
The workflow's APK is a disposable CI artifact, not a compatible update channel.

## 0.8.2 requester trust hardening

The shared Android validator now rejects unknown computer keys and all enrollment
requests in release builds. Debug builds retain the trusted ADB enrollment path;
both network transports still accept only already-enrolled computers. Existing
machine request signatures and phone biometric approval signatures are unchanged.

Both APK modes built locally with SDK 34 and JDK 25. APK signature and alignment
verification passed. Badging reports version 0.8.2/code 11, with the debuggable flag
present only in the debug APK. `git diff --check` passed.

The local build initially used a disposable signer. A separate device release
was signed with the existing enrolled app's signing key, and its signing
certificate was checked against the APK pulled from the phone before an in-place
update. The Pixel now reports 0.8.2/code 11; its foreground network service is
running and `run-as` is rejected as `package not debuggable`.

Live checks after the update:

- A phone-approved request through installed kdesu executed `id -u`, returning
  UID 0 and child exit status 0 in fresh root-owned runtime files. Existing
  enrollment continued working without a key reset or re-enrollment.
- A read-only LAN RPC signed by a fresh unknown computer key was rejected;
  Android logged `Computer is not paired`.
- A read-only LAN RPC claiming the enrolled computer ID but signed by a different
  key was rejected; Android logged `Computer signature is invalid`.

These are bounded acceptance/rejection checks, not a complete adversarial audit.

## What remains unverified

- Physical reboot and first-unlock delivery without manually opening the app.
- Deep Doze, long idle periods, vendor battery controls and sustained battery cost.
- Adversarial live debugger, replay, cancellation/concurrency or hostile-load tests.
- Independent inspection of root-private receipt/database/configuration contents.
- Other phone manufacturers, older KDE versions, other distribution packaging.
- The unfinished dedicated KDE Connect plugin and future revisions.

The [audit](SECURITY_AUDIT.md) explains the limits of static inspection. Successful
builds and ordinary approvals are useful evidence but do not establish all
security or availability properties.
