# Audit record — 2026-09-08

An independent reviewer agent performed a read-only static review of the deployed
kdesu 6.7.2-r2 integration, navi-auth 0.7.0, the Android application and elevation
guidance. The primary agent reviewed findings and local artifact/deployment
evidence. This is a public summary with workstation identities, private paths and
individual authorization records omitted. It is not a third-party certification.

## Findings and disposition

| Finding | Assessment | Current status |
| --- | --- | --- |
| Debuggable approval app / development access | High impact given authorized development access; impact inferred, not exploited live | Debug flag fixed in 0.8.1; signing custody and authorized ADB remain deployment concerns |
| Caller-supplied requester branding | Medium; confirmed in authority input validation and phone display | Open; UID is verified, branding is not |

No path bypassing the fresh phone signature or replay protection was demonstrated
in static review. This does not mean none exists. [SECURITY.md](../SECURITY.md)
describes the attack preconditions, limitations and remediation priorities.

## Inspected protections

- Installed helper was root-owned mode 4755; code directories were root-owned and
  not writable by the desktop user. Trust directories were root-owned 0700.
- Native helper showed PIE, full RELRO, non-executable stack and no RPATH/RUNPATH.
  The only direct dynamic dependency reported by readelf was libc.
- The native launcher uses a fixed isolated Python path, kernel-derived UID,
  normalized root credentials, cleared environment/descriptors, disabled core
  dumps and bounded lifetime.
- The verifier checks the pinned phone TLS binding, machine-signed nonce-bound
  RPCs, exact pending payload/certificate, fresh phone signature and single use.
- Working-directory inode and restricted execution environment are bound to the
  request. Configuration is checked again at commit.
- ready/commit separation, cancellation and exclusive postcommit ownership avoid
  intentionally falling through to a duplicate password execution.
- Android signs through a per-operation strong-biometric CryptoObject and checks
  hardware enforcement locally.

## Limits of this review

The reviewer did not read root-private configuration values, protected execution
database entries or receipt contents. No live debugger exploit, hostile network
load, adversarial replay/cancellation/concurrency campaign, physical reboot or
deep-Doze exercise was performed by this audit. Existing KDE fixture tests and
successful live authentication/root execution are separate evidence.

The deployed desktop source was frozen separately from unfinished KDE Connect
plugin development. This publication uses that deployed source at the repository
root and in the Gentoo package files. Public packaging updates the license and
homepage; patch documentation removes personal examples. These publication edits
do not claim new security fixes in the runtime protocol.

## Follow-up priorities

1. Separate steady-state approval UI and update-signing control from development
   access while preserving enrolled identities during a planned transition.
2. Make the provenance of requester labels explicit on both screens.
3. Require same-buffer or protected-snapshot execution when reviewing scripts.
4. Improve expiry reporting; validate cancellation/concurrency and service
   availability under realistic sleep and hostile-traffic conditions.
