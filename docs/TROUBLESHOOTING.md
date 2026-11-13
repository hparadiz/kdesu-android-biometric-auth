# Troubleshooting

| Symptom | Check / meaning |
| --- | --- |
| First release build refuses a missing keystore | For a brand-new phone run `./build.sh release --new-key` once. Existing users restore their own signing-key backup; do not invent a replacement key for an enrolled install. |
| No pairing panel appears in Navi after starting enrollment | KDE Connect isn't delivering to Navi, so the offer went to the phone's Downloads. In Navi open **☰ → Settings → Set up KDE Connect** and follow the steps (KDE Connect → computer → ⋮ → Plugin settings → Share and receive → Customize destination directory → ☰ → Navi Authenticator). Then cancel on the computer and press **Enroll** again. On Android 9–10 you can instead tap **Read computer messages from Downloads** on that screen and keep Navi open. |
| Opening the offer shows "Finish KDE Connect setup" instead of a code box | Expected when Navi can't follow the rest of the enrollment from Downloads (Android 11+, or Android 9–10 without storage access). Finish the setup shown, then press **Enroll** again on the computer. |
| "Pairing offer not accepted" | The chosen file is not a `navi-auth-enroll-offer-….json`, or it expired (10 minutes) or was for another session. Start enrollment again on the computer. |
| `Code does not match` | Re-type the code from the computer that is currently showing it. Five wrong entries drop that offer; start enrollment again on the computer. |
| Code accepted but the computer keeps waiting | Tap **Send confirmation again** in Navi; KDE Connect must deliver the confirmation to the same computer. The computer only accepts it from the selected device. |
| `Several phones are available` | Pass `--kdeconnect-device` with the device ID or its exact name, or run `host.py enroll` in a terminal to pick from a list. `host.py devices` lists them. |
| `Another enrollment or authentication is already running` | One request per account at a time. Finish or cancel the other one (System Settings or terminal). |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | APK signer differs. Use the original signer. Uninstalling destroys app state and enrollment. CI keys differ between runs. |
| `run-as: package not debuggable` | Expected on release. Only the ADB fallback (`enroll --serial`) needs the debug build; release enrollment uses the KDE Connect pairing code. |
| `Expected the selected Pixel` | The ADB fallback restricts devices to Pixel and Nexus 6P models; code enrollment over KDE Connect has no model check, but other hardware is not validated. |
| ADB pairing works but connection fails | Use the separate connection port displayed on the wireless-debugging main screen. It can change. |
| No notification | Check request-channel permission, foreground connection status, reachable LAN, phone IP, client isolation, background restrictions and whether the request expired. |
| Works only while app is open | Complete background setup; check force-stop, battery restrictions and Wi-Fi availability. Collect evidence after idle/reboot; do not assume an ongoing notification guarantees delivery. |
| `Invalid network frame` after about two minutes | Observed when an unapproved request expires and the phone closes its transaction. Check actual expiry/cancellation state; other framing/connection errors can produce the same text. |
| kdesu has no phone path | Check helper ownership/permissions, protected configuration, target root, visible UTF-8 command, normal scheduling and command length. `-t` and `-d` are ineligible. |
| Phone verified but command status is unclear | Inspect the child operation's result and protected execution records. A launch acknowledgement is not the command exit status. Do not automatically retry after commit. |
| Phone key invalidated | Changes to enrolled biometrics/lock-screen state may invalidate it. Recovery requires deliberate new enrollment and protected trust configuration, not an automatic bypass. |
| Certificate expired | Phone certificates last one year. Renew enrollment explicitly; update the protected snapshot. There is no unattended renewal service. |
| `host.py revoke` did not disable kdesu | Development state and root-protected trust are separate. Run `host.py authority-revoke DEVICE_ID`, use **Remove Enrollment** in System Settings, or the installed configurator's `--revoke` as administrator. |
| `kdesu` shows only the password dialog; no phone notification | The installed kdesu is not the Navi-patched build, usually because a Plasma update replaced `kde-plasma/kdesu-gui`. `host.py authority-status` and System Settings warn about this. Install the Navi kdesu-gui for your Plasma version (6.8.2-r1) and mask `kde-plasma/kdesu-gui::gentoo` (see INSTALL §5). |
| **Send Test → Over the network** fails: "Phone not reachable over the network" | In Navi, **☰ → Settings → Enable network authentication**, keep Navi's connection notification active, and keep the phone on the same Wi-Fi/LAN as the computer. KDE Connect only provides the phone's current address; the test then opens Navi's pinned TLS connection directly. |
| System Settings: "Administrator prompt status is unavailable" | `sys-auth/navi-auth` 0.8.1 is not installed, or `/usr/libexec/navi-auth/authorize` is not root-owned setuid. `host.py authority-status` shows the helper's error. |
| Administrator prompts switch is greyed out | The phone's root entry uses another KDE Connect device, or `pkexec`/`/usr/libexec/navi-auth/configure` is missing (install `sys-auth/navi-auth` 0.8.1 with polkit). **Show Administrator Command…** gives the manual command. |
| Switch fails with "Existing machine/account authority differs" | The root authority was set up from another machine identity or account. An administrator must deliberately replace it with the manual configurator. |
| System Settings: "different computer identity" warning | The root copy was configured from another state directory or before `host.py init` was rerun. Rerun the configure command shown under **Use for Administrator Prompts…**. |
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
