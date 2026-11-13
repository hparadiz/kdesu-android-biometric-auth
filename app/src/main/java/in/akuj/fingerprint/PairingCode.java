package in.akuj.fingerprint;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Release-mode enrollment bootstrap through a short code read from the computer's screen.
 *
 * <p>The computer shares a machine-signed offer over the existing KDE Connect pairing and
 * displays a one-time 8-character code. Offers only become trusted after the user types the
 * matching code: its HMAC tag binds the offer to the screen the user is looking at. The phone
 * then answers with its public key, tagged with the same code, and pins that one computer key
 * for the following biometric enrollment request. Nothing here signs with the biometric key.
 */
final class PairingCode {
    static final String FILE = "pending-enrollment.json";
    static final String HELLO = "enroll-hello.json";
    static final int NOTIFICATION_ID = 2;
    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
    private static final long MAX_LIFETIME_MS = 10 * 60_000L;
    private static final long CLOCK_SKEW_MS = 30_000L;
    private static final int MAX_OFFERS = 4;
    private static final int MAX_ATTEMPTS = 5;

    private PairingCode() { }

    /** Uppercase, drop separators and map Crockford look-alikes; null when not 8 valid symbols. */
    static String normalize(String typed) {
        if (typed == null) return null;
        StringBuilder result = new StringBuilder();
        for (char c : typed.toUpperCase(java.util.Locale.ROOT).toCharArray()) {
            if (c == '-' || c == ' ') continue;
            if (c == 'O') c = '0';
            else if (c == 'I' || c == 'L') c = '1';
            if (ALPHABET.indexOf(c) < 0) return null;
            result.append(c);
        }
        return result.length() == 8 ? result.toString() : null;
    }

    static byte[] tag(String code, String label, byte[] payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(code.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
        mac.update((label + "\n").getBytes(StandardCharsets.US_ASCII));
        return mac.doFinal(payload);
    }

    /**
     * Checks an offer's machine signature, certificate, fields and lifetime without storing it.
     * Returns the signed payload; "machine_id" is the verified certificate's key hash.
     */
    static JSONObject validateOffer(JSONObject offer) throws Exception {
        byte[] bytes = Bridge.decode(offer.getString("payload_b64"));
        JSONObject payload = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        X509Certificate machine = Bridge.certificate(offer.getString("machine_certificate_b64"));
        Bridge.validateCertificate(machine, machine, true);
        Bridge.verifyEnvelope(offer, machine);
        String machineId = Bridge.hash(machine.getPublicKey().getEncoded());
        String session = payload.getString("session_id");
        String name = payload.getString("machine_name");
        String desktop = payload.getString("desktop_device_id");
        long now = System.currentTimeMillis();
        long issued = payload.getLong("issued_at_ms");
        long expires = payload.getLong("expires_at_ms");
        if (!Challenge.DOMAIN.equals(payload.getString("domain")) || !"enroll-offer".equals(payload.getString("kind"))
                || !session.matches("[a-f0-9]{32}") || !machineId.equals(payload.getString("machine_id"))
                || !desktop.matches("[A-Za-z0-9_-]{1,128}") || name.isEmpty() || name.length() > 128
                || name.matches("(?s).*[\\x00-\\x1f\\u202a-\\u202e\\u2066-\\u2069].*")
                || issued > now + CLOCK_SKEW_MS || expires <= now || expires - issued > MAX_LIFETIME_MS
                || Bridge.decode(offer.getString("code_tag_b64")).length != 32)
            throw new IllegalArgumentException("Invalid computer pairing offer.");
        return payload;
    }

    /** Called for a KDE Connect delivery; validates the machine signature before storing. */
    static void receiveOffer(Context context, JSONObject offer) throws Exception {
        JSONObject payload = validateOffer(offer);
        String machineId = payload.getString("machine_id");
        String session = payload.getString("session_id");
        String name = payload.getString("machine_name");
        String desktop = payload.getString("desktop_device_id");
        long now = System.currentTimeMillis();
        long expires = payload.getLong("expires_at_ms");
        synchronized (Bridge.MAILBOX) {
            Bridge bridge = new Bridge(context);
            JSONObject state = load(bridge);
            JSONArray offers = new JSONArray();
            JSONArray previous = state.getJSONArray("offers");
            for (int i = 0; i < previous.length(); i++) {
                JSONObject old = previous.getJSONObject(i);
                if (old.getLong("expires_at_ms") > now && !session.equals(old.getString("session_id"))) offers.put(old);
            }
            while (offers.length() >= MAX_OFFERS) offers.remove(0);
            offers.put(new JSONObject().put("session_id", session).put("machine_id", machineId)
                    .put("machine_name", name).put("desktop_device_id", desktop)
                    .put("machine_certificate_b64", offer.getString("machine_certificate_b64"))
                    .put("payload_b64", offer.getString("payload_b64"))
                    .put("code_tag_b64", offer.getString("code_tag_b64"))
                    .put("expires_at_ms", expires).put("attempts", 0));
            state.put("offers", offers);
            bridge.write(FILE, state);
        }
        notifyOffer(context, session, name, machineId, expires - now);
        Log.i("PhoneAuthenticator", "Pairing offer stored; session=" + session);
    }

    /** Latest unexpired offer, for display only. It is not trusted until a code matches. */
    static JSONObject latestOffer(Bridge bridge) throws Exception {
        JSONArray offers = load(bridge).getJSONArray("offers");
        long now = System.currentTimeMillis();
        for (int i = offers.length() - 1; i >= 0; i--) {
            JSONObject offer = offers.getJSONObject(i);
            if (offer.getLong("expires_at_ms") > now) return offer;
        }
        return null;
    }

    /** Verified pairing (after the user's code matched), or null. */
    static JSONObject verified(Bridge bridge) throws Exception {
        JSONObject value = load(bridge).optJSONObject("verified");
        return value != null && value.getLong("expires_at_ms") > System.currentTimeMillis() ? value : null;
    }

    /**
     * Checks the typed code against the pending offers. On success the matching computer key
     * is pinned and the tagged phone hello is written for KDE Connect delivery.
     */
    static JSONObject confirm(Context context, String typed, SigningKey key) throws Exception {
        String code = normalize(typed);
        if (code == null) throw new IllegalArgumentException("Enter the 8-character code shown on the computer.");
        synchronized (Bridge.MAILBOX) {
            Bridge bridge = new Bridge(context);
            JSONObject state = load(bridge);
            JSONArray offers = state.getJSONArray("offers");
            long now = System.currentTimeMillis();
            JSONObject match = null;
            JSONArray remaining = new JSONArray();
            for (int i = 0; i < offers.length(); i++) {
                JSONObject offer = offers.getJSONObject(i);
                if (offer.getLong("expires_at_ms") <= now) continue;
                byte[] expected = Bridge.decode(offer.getString("code_tag_b64"));
                byte[] actual = tag(code, "navi-enroll-offer/v1", Bridge.decode(offer.getString("payload_b64")));
                if (match == null && MessageDigest.isEqual(expected, actual)) match = offer;
                else {
                    offer.put("attempts", offer.getInt("attempts") + 1);
                    if (offer.getInt("attempts") < MAX_ATTEMPTS) remaining.put(offer);
                }
            }
            if (match == null) {
                state.put("offers", remaining);
                bridge.write(FILE, state);
                throw new IllegalArgumentException(remaining.length() == 0
                        ? "Code does not match. Start pairing again on the computer."
                        : "Code does not match. Check the code on the computer and try again.");
            }
            String session = match.getString("session_id");
            JSONObject hello = new JSONObject().put("domain", Challenge.DOMAIN).put("kind", "enroll-hello")
                    .put("session_id", session).put("machine_id", match.getString("machine_id"))
                    .put("phone_key_id", key.id).put("public_key_spki_base64", key.publicKeyBase64())
                    .put("issued_at_ms", now);
            byte[] helloBytes = hello.toString().getBytes(StandardCharsets.UTF_8);
            bridge.write(HELLO, new JSONObject().put("request_id", session).put("kind", "enroll-hello")
                    .put("payload_b64", Bridge.encode(helloBytes))
                    .put("code_tag_b64", Bridge.encode(tag(code, "navi-enroll-hello/v1", helloBytes))));
            JSONObject verified = new JSONObject().put("session_id", session)
                    .put("machine_id", match.getString("machine_id")).put("machine_name", match.getString("machine_name"))
                    .put("desktop_device_id", match.getString("desktop_device_id"))
                    .put("expires_at_ms", match.getLong("expires_at_ms"));
            // One verified computer at a time; the other offers are no longer needed.
            bridge.write(FILE, new JSONObject().put("offers", new JSONArray()).put("verified", verified));
            context.getSystemService(NotificationManager.class).cancel(session, NOTIFICATION_ID);
            return verified;
        }
    }

    /** Snapshot of the hello document for the KDE Connect transfer, while it is still current. */
    static byte[] helloBytes(Bridge bridge, String session) throws Exception {
        JSONObject verified = verified(bridge);
        JSONObject hello = bridge.read(HELLO);
        if (verified == null || hello == null || !session.equals(verified.getString("session_id"))
                || !session.equals(hello.optString("request_id")))
            throw new IllegalStateException("Pairing code is no longer current");
        return hello.toString().getBytes(StandardCharsets.UTF_8);
    }

    static void clear(Bridge bridge) throws Exception {
        java.nio.file.Files.deleteIfExists(new java.io.File(bridge.directory(), FILE).toPath());
        java.nio.file.Files.deleteIfExists(new java.io.File(bridge.directory(), HELLO).toPath());
    }

    private static JSONObject load(Bridge bridge) throws Exception {
        JSONObject state = bridge.read(FILE);
        if (state == null) state = new JSONObject();
        if (state.optJSONArray("offers") == null) state.put("offers", new JSONArray());
        return state;
    }

    private static void notifyOffer(Context context, String session, String name, String machineId, long lifetime) {
        try {
            RequestReceiver.createChannel(context);
            Intent open = new Intent(context, MainActivity.class)
                    .setAction("in.akuj.fingerprint.OPEN_PAIRING." + session)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            PendingIntent action = PendingIntent.getActivity(context, 0, open,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification notification = new Notification.Builder(context, RequestReceiver.CHANNEL)
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle("Pair with " + name)
                    .setContentText("Enter the code shown on the computer.")
                    .setSubText("New computer · " + machineId.substring(0, 12))
                    .setContentIntent(action)
                    .addAction(new Notification.Action.Builder(null, "Enter code", action).build())
                    .setCategory(Notification.CATEGORY_EVENT)
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setTimeoutAfter(Math.max(1, lifetime))
                    .setAutoCancel(true).build();
            context.getSystemService(NotificationManager.class).notify(session, NOTIFICATION_ID, notification);
        } catch (Exception error) {
            Log.w("PhoneAuthenticator", "Pairing notification failed", error);
        }
    }
}
