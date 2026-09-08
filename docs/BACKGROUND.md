# Keep the phone available

Direct Wi-Fi uses an Android **connectedDevice foreground service** and an ongoing
connection notification. The phone and computer need a reachable local network;
guest Wi-Fi/client isolation can block delivery. ADB is only for initial enrollment
and development/install access.

## One-time setup

1. Open Navi Authenticator after enrollment. Tap **Enable network authentication**
   and approve the one-time biometric binding of its separate TLS transport key.
2. Open **Stay available → Background setup & instructions**.
3. Allow notifications. Keep **Computer connection** and **Authentication requests**
   channels enabled. The connection channel can be silent. Set requests to alerting
   and allow pop-on-screen behavior if desired.
4. Tap **Allow background operation**, accept Android's exemption prompt and check
   the app reports exclusion from battery optimization.
5. Open Android app settings. Permit background battery use; choose unrestricted
   operation if available. Disable pause/remove-permissions-if-unused behavior.
   Other manufacturers may impose additional sleeping-app/auto-start controls.
6. Wait for **Ready on your network · port 39841** and the **Navi · computer
   authentication** notification. Press Home or lock the phone.

The exemption can allow network access during Doze; it does not guarantee
uninterrupted connectivity. See Android's
[Doze documentation](https://developer.android.com/training/monitoring-device-state/doze-standby).

## Lifecycle

- The enabled setting persists. The service requests restart after process loss.
  Boot and package-replacement receivers restore an enabled listener. Credential
  storage becomes available after the first unlock following reboot.
- Closing the activity or swiping its task away does not deliberately stop the
  service. Force stop or Android's Active apps Stop does stop the app: reopen it.
- **Turn off network authentication** disables the listener and automatic startup.
  This changes availability; it does not revoke the desktop's protected trust.
- Socket failures retry from 1 second up to 30 seconds. An invalid/missing network
  identity needs manual repair by opening the app and enabling the connection.
- Android may allow dismissing an ongoing notification. Dismissal alone does not
  stop the service. The app does not keep the display on or hold a permanent wake
  lock. Battery Saver and manufacturer power management can still interrupt it.

## Check actual background delivery

With existing enrollment, app backgrounded and phone locked:

```sh
env -u DISPLAY -u WAYLAND_DISPLAY -u DBUS_SESSION_BUS_ADDRESS \
  python3 host.py authenticate --endpoint PHONE_IP:39841 \
  --application Terminal --operation 'Check background phone approval'
```

Open the request notification, unlock if necessary and approve. The terminal
must report `AUTHENTICATED`. This checks authentication without a desktop session;
it does not add sudo/PAM integration. Repeat after reboot and first unlock, and
after prolonged idle, when assessing your own device. Current evidence establishes
service availability after update and successful LAN approval, not deep-Doze
reliability or measured battery cost.
