# Remote approvals over ntfy

Normally the computer reaches Navi through KDE Connect (signed files) or Navi's
direct network listener. Both need the phone and the computer on the same local
network. **Remote approvals** add a fallback through an [ntfy](https://ntfy.sh)
server, so an approval still reaches the phone when it is on mobile data or a
different Wi-Fi.

## When it is used

Administrator prompts (kdesu), sudo, the login screen, the lock screen and
**Send Test → Automatic** choose the route per request, before it is signed:

1. **KDE Connect discovery** gives the phone's current local address. If KDE
   Connect cannot see the phone (or is not running yet, as at the SDDM login
   screen), the request goes over **ntfy**.
2. If Navi's port **39841** accepts a connection at that address, the request uses
   the **direct local network** route (Navi's pinned connection; needs
   *Enable network authentication* in Navi).
3. If the phone answers on the network but that port is closed, it uses
   **KDE Connect messages**; if that attempt fails, **ntfy**.
4. If nothing answers at that address (KDE Connect's "reachable" can lag after the
   phone leaves Wi-Fi), **ntfy**.

Nothing is published to ntfy while the phone is reachable locally. Without
remote approvals set up, steps 1 and 4 fall back to trying KDE Connect, as before.
Navi answers on the route the request arrived on; its **Send approval again**
also tries ntfy, which helps if Wi-Fi drops between the request and your fingerprint.
`journalctl -t navi-auth` shows each decision (`discovery addresses=… probe=…`,
`route=lan|kde|ntfy`).

## Setting it up

1. Enroll the phone as usual and, in Navi, keep **Stay available** set up
   (☰ → Settings → Background setup) so Navi can listen in the background.
2. On the computer: **System Settings → Navi Authenticator → ⋮** next to the
   phone → **Remote Approvals…**. Keep `https://ntfy.sh` or enter your own ntfy
   server, plus an access token if that server uses access control. Press **Set Up**.
   (Terminal: `host.py remote-setup [--kdeconnect-device PHONE] [--server URL] [--token TOKEN]`.)
3. Navi shows **Allow remote approvals**. Approve it with your fingerprint. The
   phone must be reachable through KDE Connect for this one step.
4. If **Administrator prompts** are on for the phone, System Settings asks for the
   administrator password once more to copy the remote settings into the protected
   root configuration, so `kdesu` can use ntfy too.
5. Test: **Send Test → Over ntfy (remote)**, ideally with Wi-Fi off on the phone.

To stop: **Remote Approvals… → Turn Off** on the computer
(`host.py remote-remove`), and **☰ → Settings → Remote approvals → Turn off** in
Navi. Removing the phone's enrollment also removes its remote settings.
Running Set Up again replaces the key and topics.

## How it is protected

- **Authenticity is unchanged.** Requests are still signed by the computer and
  approvals by the phone's fingerprint-protected key; Navi and the computer check
  them exactly as on the other routes. The ntfy server is never trusted to decide
  anything.
- **End-to-end encryption.** During setup the computer and Navi each create a
  fresh P-256 key pair and exchange public keys: the computer's inside its signed
  setup request, Navi's signed together with that request by the fingerprint key.
  Both derive (HKDF-SHA256) one 256-bit message key and two topic names. **The key
  and the topic names are never transmitted.** Every message is compressed
  (DEFLATE), then encrypted with AES-256-GCM, bound to its direction and topic.
- **Separate inbox per direction and per computer.** The computer publishes to
  the phone's inbox topic and reads its own inbox; a phone paired with several
  computers has separate keys and topics for each, on one background connection.
- **What the server sees:** two random topic names (`navi-` + 26 characters), the
  IP addresses of both sides, and the timing and size of messages. It cannot read
  commands, account names or computer names, and it cannot forge or replay an
  approval (requests expire after two minutes and are single-use).
- **Privileged path:** `kdesu` requests go through the root authority. The ntfy
  HTTP client runs as your desktop user and only moves ciphertext; the root
  process holds the key and never parses HTTP.
- **Icons:** over ntfy a request carries only the SHA-256 of the requesting app's
  icon. Navi shows its built-in copy (Claude, Konsole, Kitty and the common generic
  icons need no transfer at all) or a cached one; otherwise its default icon, and
  asks the computer for that one PNG, which is checked against the signed hash
  before it is shown.

## Message size

Requests use the same compressed envelope as the other routes, and name the two
certificates by hash (Navi already has them from pairing). A typical request is
under 1 KB of text, and commands up to about 5,000 characters stay within ntfy's
4 KB inline limit. Larger messages (an icon, or a very long command) are sent as
ntfy attachments. ntfy.sh allows this; a self-hosted ntfy needs
`attachment-cache-dir` configured. The computer and Navi must use the same message
format (`navi-remote/v2` since Navi 0.12.0): update both together.

## Self-hosting ntfy

Any ntfy server reachable over https from both the computer and the phone works.
With access control, create a token with read/write access to `navi-*` topics and
enter it in **Remote Approvals…**. The token is stored in your private state
directory and in Navi's private storage; it is sent to Navi inside the signed
setup request over KDE Connect.

## Battery and data

Navi keeps one HTTPS connection to the server while remote approvals are on (the
server sends a small keepalive every 45 seconds). That costs a little battery and
a few kilobytes per hour on mobile data. The connection resumes after network
changes and picks up requests sent while the phone was briefly offline.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Setup times out | The phone must be reachable through KDE Connect for setup, and Navi must show and approve **Allow remote approvals**. |
| `The ntfy server … is not reachable` | The computer cannot reach the server over https (proxy, firewall, typo in the URL). |
| Test over ntfy times out | In Navi, ☰ → Settings → Remote approvals should say *listening*. Allow Navi's notifications and background battery use (☰ → Settings → Background setup). |
| `kdesu` still fails on mobile data | Administrator prompts need the remote settings in the root copy: open **Remote Approvals…**, press **Set Up Again** and enter the administrator password when asked. `host.py authority-status` lists `remote` for the phone when it is there. |
| Requests show the default icon | Expected the first time an app asks over ntfy; the real icon appears once it arrives and is cached for next time. |
