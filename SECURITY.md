# Security model and known limitations

This is experimental software that installs a setuid root helper. The intended
boundary is: an enrolled desktop account can request an exact command, but the
protected authority executes it only after a fresh signature from the approved
phone and an explicit desktop commit. A successful normal flow is not proof that
all malicious flows are excluded.

## What approval establishes

- An approved phone key signed the exact fresh request bytes.
- The installed helper checks the kernel-derived desktop UID, protected trust,
  certificate, nonce, deadline, command context and one-time request consumption.
- Android is configured to require a strong biometric for each signing operation.
- TLS is pinned through the approved phone biometric key. Learning the IP address
  or injecting a generic notification does not authorize a command.

It does not establish that caller-supplied application branding is truthful,
that referenced scripts remain unchanged, that the phone software/update channel
is uncompromised, or that the machine has verified remote hardware attestation.

## Open findings

### Development access and APK signing custody

**High impact, conditional on development access.** The old debuggable APK exposed
its process to an authorized development host. Android 0.8.1 release mode fixes
that flag and denies `run-as`. However, possession of the app signing key plus
usable authorized ADB can allow a modified compatible update. A malicious approval
UI can misdescribe the bytes the user is authorizing. This is not extraction of
the hardware private key or a demonstrated bypass of fresh biometrics.

Keep the APK key away from a potentially compromised development account when
establishing a stronger production boundary. Disable unnecessary ADB access.
The current offline builder retains its historical development signing-key
workflow for update compatibility; non-debuggable does not mean independently
protected update signing. Never distribute a private key or silently rotate it.
See [Android app signing](https://developer.android.com/studio/publish/app-signing),
[debuggable guidance](https://developer.android.com/privacy-and-security/risks/android-debuggable),
and [Keystore limitations](https://developer.android.com/privacy-and-security/keystore).

### Requester branding can be spoofed

**Medium, local request spoofing requiring user approval.** Application name,
executable, PID, source/action strings and icon are supplied by the requester in
[`validate_start`](rootauth.py). The UID/account is kernel-checked; the branding
does not have equivalent provenance. A process under the enrolled UID can call
itself another application. Signing those fields preserves the claim but does
not prove it.

Review the exact command. The intended fix is to label requester branding as
informational and clearly distinguish it from verified machine/account context.
Kernel process metadata can improve diagnostics, but does not create strong
isolation between processes sharing a UID. Agent instructions are not an OS
boundary preventing direct helper invocation.

## Architecture limits

- **Mutable command inputs:** signing `/path/script` does not freeze that script,
  executable, imports or data. Use the same verified byte buffer or a protected
  immutable snapshot. A digest check followed by reopening a writable pathname
  leaves a replacement race.
- **Development machine key:** configuring root authority copies the machine
  key from user state. A retained user copy means a machine signature alone does
  not prove root-broker origin. Protected execution records are separate evidence.
- **Revocation:** configuration is rechecked at commit. Already committed commands
  are not undone. A stronger guarantee about concurrent revoke return versus
  consume/spawn needs a defined synchronization contract and further validation.
- **Authority status:** the setuid helper answers a read-only `status` request
  from any local account. Only the configured desktop account receives phone key
  IDs, enablement, routes and certificate expiry; other accounts learn only that
  an authority is configured. Logs, executions and certificates are never returned.
  The helper's existing `revoke` request likewise only disables the caller's own
  device. Neither request can enable a phone.
- **Enabling from System Settings:** adding a phone to the root authority always
  needs the administrator password (polkit `auth_admin`, never cached). The polkit
  entry point only runs the installed configurator, which re-validates the machine
  key, phone certificate and route as root. When started by pkexec it also refuses
  any desktop account other than the requesting user (`PKEXEC_UID`) and any source
  state directory that is not that user's own mode-0700 directory.
- **Trusted phone enrollment:** release builds enroll with a one-time
  8-character code shown on the computer and typed into the phone, carried over
  an existing KDE Connect pairing (see [Architecture](docs/ARCHITECTURE.md#code-enrollment-release-builds)).
  Trust therefore rests on the KDE Connect pairing, the user reading the code from
  the intended screen and the biometric signature. Anyone who can see the code
  *and* controls the selected paired KDE Connect device during its ten minutes
  could enroll that device; compare the computer fingerprint shown on the phone.
  The code is 40 bits and is only checked inside KDE Connect's encrypted channel.
  Enrolling only grants account-level approval; administrator prompts still need
  the separate protected configuration. Android 9 cannot receive KDE Connect
  messages, so it keeps the debug-APK and authorized-ADB bootstrap. Release
  builds reject unknown computer keys and every enrollment without a matching
  code pin in the shared validator. This flow has not yet been verified on
  hardware (see [verification record](docs/VERIFICATION.md)).
- **Biometric modality:** Android selects strength, not exclusively fingerprint.
  Locally observed hardware enforcement is not independently verified attestation.
- **Availability:** the LAN service adds network-facing code. Frames, workers and
  transaction times are bounded, but hostile-traffic availability has not been
  established. Reboot/deep-Doze behavior and battery cost require device testing.
- **Scope:** only the configured local UID and root target are supported. There
  is no PAM/sudo/login/lock-screen integration or automatic system-wide PolicyKit
  replacement. Password fallback is available before phone commit.

## Failure handling

Never interpret a sent notification, successful biometric animation, helper exit
code or process launch alone as proof of completed privileged work. Verify the
signed response and the operation's actual result. After uncertain commit, do
not retry or switch authentication routes automatically: the command may already
be running. Signed cancellation prevents acceptance of the exact pending request
when processed before commitment; loss of its network delivery does not extend TTL.

Normal expiry can currently surface as `Invalid network frame`; this is a known
error-reporting defect. Do not generalize every malformed-frame error as expiry.

## Reporting

For a non-sensitive bug or documentation issue, use
[GitHub Issues](https://github.com/hparadiz/kdesu-android-biometric-auth/issues).
Do not attach private keys, enrollment databases, signing keystores, authorization
receipts, personal commands or unredacted device logs. For a new exploitable issue,
use GitHub's private vulnerability reporting if offered by the repository; if
unavailable, ask the maintainer for a private channel without posting exploit
details. No response-time or security-support commitment is promised.

See the [bounded audit](docs/SECURITY_AUDIT.md) and
[verification record](docs/VERIFICATION.md) for what was actually checked.
