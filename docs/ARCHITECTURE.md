# Architecture

## Components and execution boundary

```mermaid
sequenceDiagram
    participant U as User
    participant K as kdesu dialog
    participant H as Protected helper
    participant P as Android authenticator
    K->>H: start: exact command, context, cwd, environment
    H->>P: Machine-signed fresh challenge over pinned TLS
    P->>U: Review command and request strong biometric
    U->>P: Approve biometric operation
    P->>H: Signature over exact request bytes
    H->>H: Verify certificate, signature, nonce and deadline
    H->>K: ready
    K->>H: commit (phone path becomes exclusive)
    H->>H: Recheck configuration, consume proof, launch command
    H->>P: Signed execution receipt
    H->>K: executed with child PID
```

`authorize.c` is a small root-owned setuid executable. It requires private process
pipes, derives the original caller UID from the kernel, clears inherited
environment/groups/descriptors, disables core dumps and invokes the system default
`/usr/bin/python3` in isolated mode (`-I`). On Gentoo that is python-exec, which
follows the root-owned `eselect python` setting; the helper's cleared environment
means `EPYTHON` cannot redirect it to another interpreter. `rootauth.py` owns authorization and execution.
No desktop listening socket or persistent desktop authentication service is needed.

The helper must be `/usr/libexec/navi-auth/authorize`, with a protected directory
chain. kdesu checks its ownership and permissions before launching it. Code and
trust must be installed by an administrator; running a user-writable verifier as
root would destroy this boundary.

`host.py` is the unprivileged enrollment and diagnostic CLI. Its displayed command
is metadata. Only the installed authority executes commands.

## Three distinct keys

| Identity | Storage and use |
| --- | --- |
| Phone biometric P-256 key | Android Keystore; per-operation strong biometric required; signs approvals |
| Phone TLS transport key | Separate Android Keystore key; its certificate is bound by the biometric key once when enabling LAN |
| Machine P-256 authority key | Desktop state; issues phone certificates and signs requests/receipts |

The APK update-signing key is a **fourth, separate identity**. It determines who
can supply compatible app updates, not who can approve a command.

The machine issues a one-year non-CA X.509 certificate for the enrolled phone
public key; its own CA certificate lasts ten years. The phone pins the computer
key, and the computer keeps an explicit approved-phone record. An unknown machine
cannot enroll itself over the LAN listener.

### Code enrollment (release builds)

Initial trust comes from a one-time code that the user reads on the computer and
types into the phone, carried over an existing KDE Connect pairing:

1. `host.py enroll` (or the System Settings page) shares a machine-signed
   `enroll-offer` with the selected KDE Connect device and shows an 8-character
   Crockford-base32 code (40 bits, 10-minute lifetime). The offer carries the
   machine CA certificate, host name, the desktop's KDE Connect ID and
   `HMAC-SHA256(code, "navi-enroll-offer/v1\n" || payload)`.
2. The phone stores up to four unexpired offers but trusts none of them. When the
   typed code matches one offer's tag (five wrong attempts drop an offer), the
   phone pins that machine key and desktop route for the offer's lifetime and
   shares back an `enroll-hello`: its public key and key ID tagged with the same
   code under the `navi-enroll-hello/v1` label.
3. The computer accepts the hello only from the selected device, verifies the tag
   and key ID, issues the phone certificate and sends the normal `enroll` request
   bound to the `kdeconnect-share` transport.
4. `Bridge.validate` accepts an unknown machine or an `enroll` request only when
   it matches the pinned key and returns to the same desktop route. The usual
   biometric signature then proves possession; the pin is deleted on success.

Offers from other paired devices or apps cannot match the code the user is
reading, and all messages stay inside KDE Connect's paired channel, so the short
code is not exposed to offline guessing. Delivery to the phone is automatic with
Navi as the KDE Connect destination (Android 10+). On Android 9–10 Navi can
instead import recent `navi-auth-*.json` files from `Download/` while it is open.
A saved offer the user opens with Navi or the file picker (offers only) is fully
validated, but it is stored for code entry only when Navi can follow the rest of
the enrollment from Downloads. Otherwise (Android 11+, or no storage access) Navi
discards it and shows the KDE Connect destination setup, because the enrollment
request would land where Navi cannot read it. On
Android 9 the documents provider only serves Navi's outgoing replies and is not
offered as a destination folder.

Release builds reject every other enrollment in the shared validator, before the
request is shown, regardless of delivery route. A debuggable build still accepts
the original trusted ADB bootstrap (`host.py enroll --serial`), kept as a
fallback for Android 9 devices. A valid signature from an unknown key never
establishes trust on its own.

Android uses `BiometricPrompt.CryptoObject(Signature)` with a per-operation strong
biometric requirement. This is Android biometric strength selection, not a
fingerprint-only modality guarantee. A qualifying face biometric may also be
offered. Hardware enforcement is checked locally; there is no remote attestation
verifier in this project. Fingerprint templates do not leave Android.

## Wire format and freshness

The phone protocol domain is `android-linux-fingerprint/v1`. JSON envelopes carry
base64-encoded exact UTF-8 payload bytes and DER ECDSA/SHA-256 signatures. Public
keys are DER SubjectPublicKeyInfo; certificates are DER X.509. Verifiers check
the original decoded bytes rather than reserializing received objects.

Requests bind request ID, random 256-bit nonce, machine/phone key IDs, approved
certificate hash, operation, issue/expiry times and display context. Privileged
requests additionally bind the exact `/bin/sh -c` command, target credentials,
held working-directory inode, restricted environment and desktop dialog ID.
Approval and commit share a 120-second deadline. SQLite consumes each pending
proof once. A certificate by itself is not a reusable authentication token.

Direct LAN uses TLS 1.3 on Android 10+. Android 9 uses TLS 1.2 with only
ECDHE-ECDSA/AES-GCM suites; the host accepts both. Before sending command metadata,
the host verifies that
the peer certificate exactly matches the TLS binding signed by the approved phone
biometric key. Each RPC is machine-signed and bound to a fresh server nonce.
Frames and transaction lifetimes are bounded. Certificate pinning authenticates
the endpoint even when routing information comes from KDE Connect.

## Concurrent enrolled phones

The protected registry contains up to 32 phone entries, each with an approved
certificate, enablement and route. Legacy single-phone configuration remains
readable. One desktop dialog creates independent signed challenges and nonces for
all enabled phones concurrently, with a shared command/context and deadline.
Transport failures, declines and invalid responses are isolated to their phone.

The first cryptographically verified response selects the winner. The helper
withdraws competing requests, then uses the existing ready/commit protocol to
consume only the winning proof and launch the command once. Cancellation has
priority if it arrives alongside an approval. Slow transfer completion precedes
its signed withdrawal; file transports retain cancellation tombstones. This
fan-out does not allow multiple desktop dialogs to share execution authority.

Desk reader mode affects only prompt initiation in the Android activity. It
checks foreground focus, unlocked state, validated request kind, expiry and
withdrawal before entering the unchanged per-use CryptoObject flow. The last
automatically prompted request ID persists to prevent prompt loops after restart.
Enrollment is never automatically prompted.

## One execution owner

The private-pipe protocol is `navi-auth-exec/v1`: `start`, `ready`, `commit`,
`executed`, `cancel`, `canceled`, and errors. Password entry remains available
before commit. Selecting another path cancels the phone path before proceeding.
Once committed, a missing acknowledgement means **uncertain execution**; no
automatic password fallback or retry is allowed. Inspect the operation's result
before considering another invocation.

The root command has a separate session and redirected streams. Its launch can
outlive the helper and dialog. An `executed` message with a positive PID confirms
launch only. The native helper has a 180-second maximum lifetime; KDE has a
separate 20-second postcommit acknowledgement deadline.

The authority accepts one configured desktop UID and root as target, one active
request at a time, printable commands up to 512 characters, normal scheduling,
visible commands and nonterminal execution. `kdesu -t` and `-d` are ineligible.

## Trust, revocation and records

Development state defaults to `.state/` alongside `host.py`; use the global
`--state-dir` option before the subcommand to choose another private directory.
The installed snapshot lives in `/etc/navi-auth/config.json` and
`/var/lib/navi-auth/`, root-owned 0700, with credentials mode 0600. The execution
database and `last-execution.json` store approval/receipt evidence;
`commands.log` receives command diagnostics. These can contain sensitive commands.

The setuid helper also accepts two non-executing requests from the configured
desktop account, each a single line on the same pipe protocol: `status` returns a
read-only summary of the protected configuration (phone key IDs, enablement,
transport, KDE Connect route and certificate expiry; nothing for other accounts),
and `revoke` disables the caller's own KDE Connect device. `host.py
authority-status` and `authority-revoke` and the System Settings page use them.
Neither takes the authority lock, and neither can add or enable a phone. Enabling
goes through polkit (`in.akuj.navi-auth.configure-authority`, `auth_admin`) to the
fixed `/usr/libexec/navi-auth/configure` wrapper, i.e. the same configurator an
administrator would run, limited to the requesting user's own account and state.

`host.py revoke` only changes development state. The installed configurator's
`--revoke` disables all protected phones, or one when combined with
`--phone-key-id`. Configuration writes and execution commit share a lock, and the
exact configuration digest is rechecked at commit. A change before commit prevents
execution; an already committed command is not undone. Stopping phone notifications
alone is not revocation.

The current phone UI lists paired computers (**☰ → Paired computers**) and
supports **Reset key and all pairings** (**☰ → Settings**). That reset affects every computer and invalidates existing enrollment;
there is no polished per-computer forget workflow yet.

## KDE Connect options

The included `kdeconnect_transport.py` uses existing file sharing with Navi's
Android DocumentsProvider on Android 10+. Select Navi Authenticator as KDE Connect's custom
destination folder, grant access, then use
`host.py authenticate --kdeconnect-messages DEVICE_ID`. Signed replies and
cancellations travel through the existing pairing. Ordinary files go to Downloads.
Both transports share the phone's single active request mailbox.

`--kdeconnect-device DEVICE_ID` instead resolves the current IP and still uses
direct TLS; it is not the file-sharing transport. The protected configurator
supports `lan` and `kdeconnect-share`. These modes require KDE Connect/D-Bus
dependencies where used. The dedicated new KDE Connect plugin is unfinished and
is outside this published deployed snapshot.
