package in.akuj.fingerprint;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.UserManager;
import android.util.Log;

/** Restore the user's enabled listener after unlock at boot or an in-place update. */
public final class NetworkRestartReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) return;
        // Pairings and transport identity remain in credential-protected storage.
        if (!context.getSystemService(UserManager.class).isUserUnlocked() || !NetworkService.enabled(context)) return;
        try {
            context.startForegroundService(new Intent(context, NetworkService.class));
        } catch (IllegalStateException | SecurityException error) {
            NetworkService.status = "Open Navi to resume network authentication";
            Log.w("PhoneAuthenticator", "Android prevented listener restart", error);
            NetworkService.showRecoveryNotification(context);
        }
    }
}
