package in.akuj.fingerprint;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.json.JSONObject;

/** TLS LAN delivery. Every RPC is authenticated with an already pinned computer key. */
public final class NetworkService extends Service {
    static final int PORT = 39841;
    private static final int LIMIT = 131072;
    private static final int NOTIFICATION_ID = 2;
    static final String CHANNEL = "computer_connection";
    private static final int RECOVERY_NOTIFICATION_ID = 3;
    static volatile String status = "Network connection is off";
    static volatile boolean running;
    private volatile SSLServerSocket listener;
    private volatile boolean stopping;
    private Thread listenerThread;
    private final ThreadPoolExecutor clients = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4));
    private Bridge bridge;
    private SigningKey key;
    private final Object mailbox = Bridge.MAILBOX;
    private final java.util.Timer deadlines = new java.util.Timer("navi-lan-deadlines", true);
    private final java.util.Set<SSLSocket> sockets = java.util.concurrent.ConcurrentHashMap.newKeySet();

    @Override public IBinder onBind(Intent intent) { return null; }

    static boolean enabled(Context context) {
        return context.getSharedPreferences("network", 0).getBoolean("enabled", false);
    }

    static void createChannel(Context context) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Computer connection", NotificationManager.IMPORTANCE_LOW));
    }

    static void showRecoveryNotification(Context context) {
        createChannel(context);
        PendingIntent open = PendingIntent.getActivity(context, 3, new Intent(context, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        context.getSystemService(NotificationManager.class).notify(RECOVERY_NOTIFICATION_ID,
                new Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_notification)
                        .setContentTitle("Navi needs your attention").setContentText(status)
                        .setContentIntent(open).setAutoCancel(true).build());
    }

    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        PendingIntent setup = PendingIntent.getActivity(this, 2, new Intent(this, BackgroundSetupActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("Navi · computer authentication")
                .setContentText(status).setStyle(new Notification.BigTextStyle().bigText(status
                        + "\nListening in the background for your paired computers."))
                .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).setShowWhen(false)
                .addAction(new Notification.Action.Builder(null, "Background setup", setup).build())
                .setCategory(Notification.CATEGORY_SERVICE);
        if (Build.VERSION.SDK_INT >= 31) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        return builder.build();
    }

    private void publishStatus(String message) {
        synchronized (mailbox) {
            if (stopping) return;
            status = message;
            getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, notification());
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (!enabled(this)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        createChannel(this);
        if (!running) status = "Starting network connection…";
        startForeground(NOTIFICATION_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        getSystemService(NotificationManager.class).cancel(RECOVERY_NOTIFICATION_ID);
        if (!running) {
            running = true;
            listenerThread = new Thread(this::listen, "navi-lan-listener");
            listenerThread.start();
        }
        return START_STICKY;
    }

    private void listen() {
        javax.net.ssl.SSLServerSocketFactory socketFactory;
        try {
            bridge = new Bridge(this);
            key = SigningKey.prepare();
            NetworkIdentity identity = new NetworkIdentity();
            if (!identity.approved(bridge, key) || bridge.pairings().length() == 0)
                throw new IllegalStateException("Enable the network connection in Navi first.");
            socketFactory = identity.context().getServerSocketFactory();
        } catch (Exception error) {
            if (!stopping) {
                status = "Open Navi and enable network authentication again";
                Log.e("PhoneAuthenticator", "LAN identity unavailable", error);
                showRecoveryNotification(this);
                stopSelf();
            }
            return;
        }
        // A lost socket must not permanently disable an opted-in listener.
        // Block in accept while idle; no polling, repeating alarms or permanent wake lock.
        int retrySeconds = 1;
        while (!stopping) {
            try (SSLServerSocket server = (SSLServerSocket) socketFactory.createServerSocket()) {
                listener = server;
                server.setReuseAddress(true);
                server.setEnabledProtocols(new String[]{"TLSv1.3"});
                server.bind(new InetSocketAddress(PORT), 4);
                publishStatus("Ready on your network · port " + PORT);
                retrySeconds = 1;
                while (!stopping) {
                    SSLSocket socket = (SSLSocket) server.accept();
                    socket.setSoTimeout(5000);
                    sockets.add(socket);
                    try { clients.execute(() -> handle(socket)); }
                    catch (java.util.concurrent.RejectedExecutionException busy) { sockets.remove(socket); socket.close(); }
                }
            } catch (Exception error) {
                if (stopping) break;
                Log.w("PhoneAuthenticator", "LAN listener will retry", error);
                publishStatus("Reconnecting · retrying in " + retrySeconds + " seconds");
                try { Thread.sleep(retrySeconds * 1000L); }
                catch (InterruptedException stopped) { Thread.currentThread().interrupt(); break; }
                retrySeconds = Math.min(30, retrySeconds * 2);
            } finally { listener = null; }
        }
    }

    private void handle(SSLSocket socket) {
        java.util.TimerTask deadline = new java.util.TimerTask() {
            @Override public void run() { try { socket.close(); } catch (Exception ignored) { } }
        };
        try (SSLSocket connection = socket) {
            if (stopping) return;
            deadlines.schedule(deadline, 10000);
            connection.startHandshake();
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            String nonce = Bridge.encode(random);
            InputStream input = connection.getInputStream();
            OutputStream output = connection.getOutputStream();
            send(output, new JSONObject().put("identity", bridge.read("network-identity.json")).put("nonce", nonce));
            JSONObject envelope = receive(input);
            byte[] raw = Bridge.decode(envelope.getString("payload_b64"));
            if (raw.length > 98304) throw new IllegalArgumentException("RPC too large");
            JSONObject rpc = new JSONObject(new String(raw, StandardCharsets.UTF_8));
            String machine = rpc.getString("machine_id");
            if (!machine.matches("[a-f0-9]{64}") || !nonce.equals(rpc.getString("server_nonce"))
                    || !Challenge.DOMAIN.equals(rpc.getString("domain"))
                    || !"network-rpc".equals(rpc.getString("kind")) || !key.id.equals(rpc.getString("phone_key_id")))
                throw new IllegalArgumentException("Invalid network request");
            JSONObject paired = bridge.pairings().optJSONObject(machine);
            if (paired == null) throw new IllegalArgumentException("Computer is not paired");
            Bridge.verifyEnvelope(envelope, Bridge.certificate(paired.getString("machine_certificate_b64")));
            // Serialize mailbox changes so paired computers cannot replace each other's active request.
            JSONObject value;
            synchronized (mailbox) {
                if (stopping) throw new IllegalStateException("Network authentication is off");
                value = exchange(rpc, machine);
            }
            send(output, new JSONObject().put("ok", true).put("value", value == null ? JSONObject.NULL : value));
        } catch (Exception error) {
            // An invalid peer gets no metadata and cannot trigger an Android notification.
            Log.w("PhoneAuthenticator", "LAN request rejected", error);
        } finally {
            deadline.cancel();
            deadlines.purge();
            sockets.remove(socket);
        }
    }

    private JSONObject exchange(JSONObject rpc, String machine) throws Exception {
        String operation = rpc.getString("operation");
        String name = rpc.getString("name");
        String id = rpc.getString("request_id");
        if (!id.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("Invalid request ID");
        if ("write".equals(operation) && "request.json".equals(name)) {
            JSONObject value = rpc.getJSONObject("value");
            checkSize(value);
            Challenge request = bridge.validate(value, key);
            if (!"authenticate".equals(request.kind) || !id.equals(request.id)
                    || !machine.equals(request.payload.getString("machine_id")))
                throw new IllegalArgumentException("Request does not match sender");
            JSONObject old = bridge.read("request.json");
            if (old != null) {
                try {
                    Challenge previous = bridge.validate(old, key);
                    if (previous.id.equals(id)) {
                        if (!Arrays.equals(previous.bytes, request.bytes)) throw new IllegalArgumentException("Changed request");
                        return null; // Idempotent redelivery cannot repost or clear a completed proof.
                    }
                    JSONObject response = bridge.read("response.json");
                    boolean finished = bridge.canceled(previous) || response != null && previous.id.equals(response.optString("request_id"))
                            && ("declined".equals(response.optString("status")) || bridge.receipt(previous, response));
                    if (!finished) throw new IllegalStateException("Another computer request is active");
                } catch (Challenge.Expired expired) { /* Old request no longer owns the mailbox. */ }
            }
            bridge.write(name, value);
            RequestReceiver.refreshNotification(this, id, false);
            return null;
        }
        JSONObject current = bridge.read("request.json");
        if (current == null) throw new IllegalArgumentException("No current request");
        boolean terminal = "write".equals(operation) && ("receipt.json".equals(name) || "cancel.json".equals(name));
        Challenge request = bridge.validate(current, key, terminal);
        if (!id.equals(request.id) || !machine.equals(request.payload.getString("machine_id")))
            throw new IllegalArgumentException("Request is owned by another computer");
        if ("read".equals(operation) && "response.json".equals(name)) {
            JSONObject response = bridge.read(name);
            return response != null && id.equals(response.optString("request_id")) ? response : null;
        }
        if ("write".equals(operation)) {
            JSONObject value = rpc.getJSONObject("value");
            checkSize(value);
            if ("cancel.json".equals(name)) {
                if (!bridge.canceled(request, value)) throw new IllegalArgumentException("Wrong cancellation");
            } else if ("receipt.json".equals(name)) {
                JSONObject response = bridge.read("response.json");
                if (response == null || !id.equals(response.optString("request_id")) || !bridge.receipt(request, response, value))
                    throw new IllegalArgumentException("Wrong receipt");
            } else throw new IllegalArgumentException("Unknown mailbox operation");
            bridge.write(name, value);
            if ("cancel.json".equals(name)) RequestReceiver.refreshNotification(this, id, true);
            return null;
        }
        throw new IllegalArgumentException("Unknown network operation");
    }

    private static void checkSize(JSONObject value) {
        if (value.toString().getBytes(StandardCharsets.UTF_8).length > 65536) throw new IllegalArgumentException("Message too large");
    }

    private static JSONObject receive(InputStream input) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int count = 0; count < LIMIT; count++) {
            int next = input.read();
            if (next == -1) throw new java.io.EOFException();
            if (next == '\n') return new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
            bytes.write(next);
        }
        throw new IllegalArgumentException("Network message too large");
    }

    private static void send(OutputStream output, JSONObject value) throws Exception {
        byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length >= LIMIT) throw new IllegalArgumentException("Network message too large");
        output.write(bytes);
        output.write('\n');
        output.flush();
    }

    @Override public void onDestroy() {
        synchronized (mailbox) { stopping = true; }
        try { if (listener != null) listener.close(); } catch (Exception ignored) { }
        if (listenerThread != null) listenerThread.interrupt();
        clients.shutdownNow();
        for (SSLSocket socket : sockets) { try { socket.close(); } catch (Exception ignored) { } }
        deadlines.cancel();
        running = false;
        if (status.startsWith("Ready") || status.startsWith("Starting") || status.startsWith("Reconnecting"))
            status = "Network connection is off";
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
