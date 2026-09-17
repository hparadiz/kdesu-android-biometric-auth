# Troubleshooting

| Symptom | Check / meaning |
| --- | --- |
| First release build refuses a missing keystore | A fresh setup starts with the explicit debug enrollment build. Existing users restore their own signing-key backup; do not invent a replacement key for an enrolled install. |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | APK signer differs. Use the original signer. Uninstalling destroys app state and enrollment. CI keys differ between runs. |
| `run-as: package not debuggable` | Expected on release. ADB mailbox enrollment/authentication needs the explicit debug build; normal release authentication uses LAN or configured KDE Connect sharing. |
| `Expected the selected Pixel` | The enrollment helper currently restricts devices to Pixel models; other hardware is not validated. |
| ADB pairing works but connection fails | Use the separate connection port displayed on the wireless-debugging main screen. It can change. |
| No notification | Check request-channel permission, foreground connection status, reachable LAN, phone IP, client isolation, background restrictions and whether the request expired. |
| Works only while app is open | Complete background setup; check force-stop, battery restrictions and Wi-Fi availability. Collect evidence after idle/reboot; do not assume an ongoing notification guarantees delivery. |
| `Invalid network frame` after about two minutes | Observed when an unapproved request expires and the phone closes its transaction. Check actual expiry/cancellation state; other framing/connection errors can produce the same text. |
| kdesu has no phone path | Check helper ownership/permissions, protected configuration, target root, visible UTF-8 command, normal scheduling and command length. `-t` and `-d` are ineligible. |
| Phone verified but command status is unclear | Inspect the child operation's result and protected execution records. A launch acknowledgement is not the command exit status. Do not automatically retry after commit. |
| Phone key invalidated | Changes to enrolled biometrics/lock-screen state may invalidate it. Recovery requires deliberate new enrollment and protected trust configuration, not an automatic bypass. |
| Certificate expired | Phone certificates last one year. Renew enrollment explicitly; update the protected snapshot. There is no unattended renewal service. |
| `host.py revoke` did not disable kdesu | Development state and root-protected trust are separate. Use the installed configurator's `--revoke` as administrator. |
| Connection fails after Wi-Fi changes | Restore the phone’s Wi-Fi and press **Retry** beside the connection error. Each attempt uses a fresh request and resolves the current phone address. Retry is unavailable after execution may have started. |
| CLI works but kdesu cannot reach phone | Configure LAN with `--kdeconnect-device` to follow the current paired phone address. Connection failures trigger one bounded KDE Connect discovery refresh. Check that the configured pairing is current, not an old offline device entry. |

## Diagnostic boundaries

Use `python3 host.py status` to inspect the selected user-state identities. A
custom state directory is a global option:

```sh
python3 host.py --state-dir /path/to/private/state status
```

An administrator can run the installed `rootauth.py --check` to check protected
configuration. Do not dump private state or signing keys into an issue. Protected
`last-execution.json`, `executions.sqlite3` and `commands.log` can contain command
metadata and should be handled accordingly.

If development ADB is intentionally enabled for a diagnostic, narrow Android logs:

```sh
adb -s PHONE_SERIAL logcat -d -v brief -s PhoneAuthenticator:I AndroidRuntime:E
```

Review/redact logs before sharing. Runtime authentication does not require enabling
ADB. After a desktop request expires, start a new request only after determining
that no privileged command was committed by the previous attempt.
