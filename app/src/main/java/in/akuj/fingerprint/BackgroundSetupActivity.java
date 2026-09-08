package in.akuj.fingerprint;

import android.Manifest;
import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

/** User-controlled Android permissions and instructions for the persistent listener. */
public final class BackgroundSetupActivity extends Activity {
    static boolean batteryAllowed(Context context) {
        return context.getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(context.getPackageName());
    }

    static boolean notificationsAllowed(Context context) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (!manager.areNotificationsEnabled()) return false;
        for (String id : new String[]{RequestReceiver.CHANNEL, NetworkService.CHANNEL}) {
            NotificationChannel channel = manager.getNotificationChannel(id);
            if (channel != null && channel.getImportance() == NotificationManager.IMPORTANCE_NONE) return false;
        }
        return true;
    }

    static String summary(Context context) {
        if (!notificationsAllowed(context)) return "Setup needed · allow both notification categories";
        if (!batteryAllowed(context)) return "Setup needed · allow background battery use";
        return NetworkService.enabled(context) ? "Background permissions ready · restarts after reboot and unlock"
                : "Permissions ready · enable network authentication";
    }

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        setContentView(R.layout.background_setup);
        RequestReceiver.createChannel(this);
        NetworkService.createChannel(this);
        findViewById(R.id.background_done).setOnClickListener(v -> finish());
        findViewById(R.id.background_notifications).setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 20);
            } else openSettings(new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()));
        });
        findViewById(R.id.background_connection_channel).setOnClickListener(v -> openChannel(NetworkService.CHANNEL));
        findViewById(R.id.background_request_channel).setOnClickListener(v -> openChannel(RequestReceiver.CHANNEL));
        findViewById(R.id.background_battery).setOnClickListener(v -> {
            Intent settings = batteryAllowed(this) ? new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                    : new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).setData(Uri.parse("package:" + getPackageName()));
            openSettings(settings);
        });
        findViewById(R.id.background_app_settings).setOnClickListener(v -> openSettings(appSettings()));
    }

    private Intent appSettings() {
        return new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(Uri.parse("package:" + getPackageName()));
    }

    private void openChannel(String id) {
        openSettings(new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()).putExtra(Settings.EXTRA_CHANNEL_ID, id));
    }

    private void openSettings(Intent intent) {
        try { startActivity(intent); }
        catch (android.content.ActivityNotFoundException | SecurityException unavailable) {
            try { startActivity(appSettings()); }
            catch (android.content.ActivityNotFoundException | SecurityException missing) {
                Toast.makeText(this, "Open Android Settings → Apps → Navi Authenticator", Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override protected void onResume() {
        super.onResume();
        ((TextView) findViewById(R.id.background_notification_status)).setText(notificationsAllowed(this)
                ? "Allowed · check both categories below" : "Action needed · notifications or a category are blocked");
        ((TextView) findViewById(R.id.background_battery_status)).setText(batteryAllowed(this)
                ? "Allowed · excluded from battery optimization" : "Action needed · Android can suspend network access during sleep");
        ((Button) findViewById(R.id.background_battery)).setText(batteryAllowed(this)
                ? "Review battery settings" : "Allow background operation");
        ((TextView) findViewById(R.id.background_service_status)).setText(NetworkService.enabled(this)
                ? "Enabled · " + NetworkService.status : "Off · return to Navi and enable network authentication");
    }

    @Override public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(code, permissions, results);
        if (code != 20) return;
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            ((TextView) findViewById(R.id.background_notification_status)).setText(notificationsAllowed(this)
                    ? "Notifications allowed" : "Allow both categories below");
        } else if (results.length > 0) {
            openSettings(new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()));
        }
    }
}
