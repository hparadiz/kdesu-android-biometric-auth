package in.akuj.fingerprint;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.SystemClock;
import android.util.Log;
import org.json.JSONObject;

/** An explicit, shell-permission-protected delivery signal for the ADB MVP. */
public final class RequestReceiver extends BroadcastReceiver {
    static final String CHANNEL = "authentication_requests";
    static final int NOTIFICATION_ID = 1;

    static void createChannel(Context context) {
        NotificationChannel channel = new NotificationChannel(CHANNEL, "Authentication requests", NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Approve signed requests from your paired computers");
        channel.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        context.getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    @Override public void onReceive(Context context, Intent intent) {
        boolean cancellation = "in.akuj.fingerprint.REQUEST_CANCELED".equals(intent.getAction());
        if (!cancellation && !"in.akuj.fingerprint.REQUEST_READY".equals(intent.getAction())) return;
        String expectedId = intent.getStringExtra("request_id");
        if (expectedId == null || !expectedId.matches("[a-f0-9]{32}")) return;
        PendingResult pending = goAsync();
        new Thread(() -> {
            try { refreshNotification(context, expectedId, cancellation); }
            finally { pending.finish(); }
        }, "request-notification").start();
    }

    static void refreshNotification(Context context, String expectedId, boolean cancellation) {
            try {
                Bridge bridge = new Bridge(context);
                JSONObject envelope = bridge.read("request.json");
                if (envelope == null) return;
                Challenge request = bridge.validate(envelope, SigningKey.prepare());
                if (!expectedId.equals(request.id) || request.expired()) return;
                if (bridge.canceled(request)) {
                    context.getSystemService(NotificationManager.class).cancel(request.id, NOTIFICATION_ID);
                    Log.i("PhoneAuthenticator", "Verified computer cancellation; request=" + request.id);
                    return;
                }
                if (cancellation) return;
                JSONObject response = bridge.read("response.json");
                if (response != null && request.id.equals(response.optString("request_id"))) return;
                Bitmap requester = RequesterIcon.decode(request.context);
                createChannel(context);
                Intent open = new Intent(context, MainActivity.class)
                        .setAction("in.akuj.fingerprint.OPEN_REQUEST." + request.id)
                        .putExtra("request_id", request.id)
                        .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                PendingIntent action = PendingIntent.getActivity(context, 0, open,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                Notification.Builder notification = new Notification.Builder(context, CHANNEL)
                        .setSmallIcon(R.drawable.ic_notification)
                        .setContentTitle(request.machineName + " · " + request.context.getString("application"))
                        .setContentText(request.operation)
                        .setSubText((request.kind.equals("enroll") ? "New computer · " : "Paired computer · ")
                                + request.payload.getString("machine_id").substring(0, 12))
                        .setStyle(new Notification.BigTextStyle().bigText(request.operation + "\nAccount: "
                                + request.context.getString("target_user")))
                        .setContentIntent(action)
                        .addAction(new Notification.Action.Builder(null, "Review and authenticate", action).build())
                        .setCategory(Notification.CATEGORY_EVENT)
                        .setVisibility(Notification.VISIBILITY_PRIVATE)
                        .setTimeoutAfter(Math.max(1, request.deadline - SystemClock.elapsedRealtime()))
                        .setAutoCancel(true);
                if (requester != null) notification.setLargeIcon(requester);
                NotificationManager manager = context.getSystemService(NotificationManager.class);
                // The MVP mailbox has one active request; retire older notifications.
                for (android.service.notification.StatusBarNotification previous : manager.getActiveNotifications()) {
                    if (previous.getId() == NOTIFICATION_ID) manager.cancel(previous.getTag(), NOTIFICATION_ID);
                }
                if (!manager.areNotificationsEnabled()) throw new IllegalStateException("Enable notifications in Android settings.");
                manager.notify(request.id, NOTIFICATION_ID, notification.build());
                Log.i("PhoneAuthenticator", "Verified request notification posted; request=" + request.id);
            } catch (Exception error) {
                Log.e("PhoneAuthenticator", "Request notification rejected", error);
            }
    }
}
