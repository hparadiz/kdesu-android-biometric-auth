package in.akuj.fingerprint;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.DocumentsContract;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import org.json.JSONObject;

/** Signed mailbox carried by stock KDE Connect file sharing. */
final class KdeConnectInbox {
    static final String AUTHORITY = "in.akuj.fingerprint.documents";
    static final String PACKAGE = "org.kde.kdeconnect_tp";

    static String desktop(Challenge request) throws Exception {
        JSONObject transport = request.payload.optJSONObject("transport");
        if (transport == null || !"kdeconnect-share".equals(transport.optString("kind"))) return null;
        String id = transport.getString("desktop_device_id");
        if (!id.matches("[A-Za-z0-9_-]{1,128}")) throw new IllegalArgumentException("Invalid paired computer route.");
        return id;
    }

    static boolean uses(Challenge request) {
        return request != null && request.payload.optJSONObject("transport") != null
                && "kdeconnect-share".equals(request.payload.optJSONObject("transport").optString("kind"));
    }

    static void sendResponse(Activity activity, Challenge request) throws Exception {
        String device = desktop(request);
        if (device == null) return;
        JSONObject response = new Bridge(activity).read("response.json");
        if (response == null || !request.id.equals(response.optString("request_id")))
            throw new IllegalStateException("This approval is no longer available.");
        if (request.expired()) throw new IllegalStateException("The request expired before delivery.");
        // Reuse KDE Connect's persisted read/write inbox tree grant. Its upload
        // begins after ShareActivity finishes, outliving that activity's Intent grant.
        Uri uri = DocumentsContract.buildDocumentUriUsingTree(
                DocumentsContract.buildTreeDocumentUri(AUTHORITY, "navi"), "response:" + request.id);
        Intent share = new Intent(Intent.ACTION_SEND)
                .setComponent(new ComponentName(PACKAGE, "org.kde.kdeconnect.plugins.share.ShareActivity"))
                .setType("application/json").putExtra("deviceId", device)
                .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        share.setClipData(ClipData.newRawUri("Signed authentication response", uri));
        activity.startActivity(share);
    }

    static void receive(Context context, byte[] bytes) throws Exception {
        if (bytes.length > 65536) throw new IllegalArgumentException("Authentication file is too large.");
        JSONObject mail = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        String name = mail.getString("name");
        String id = mail.getString("request_id");
        if (!Challenge.DOMAIN.equals(mail.getString("domain")) || !"kdeconnect-mail".equals(mail.getString("kind"))
                || !id.matches("[a-f0-9]{32}") || !Arrays.asList("request.json", "receipt.json", "cancel.json").contains(name))
            throw new IllegalArgumentException("Invalid authentication file.");
        synchronized (Bridge.MAILBOX) {
            Bridge bridge = new Bridge(context);
            SigningKey key = SigningKey.prepare();
            JSONObject value = mail.getJSONObject("value");
            boolean requestMessage = "request.json".equals(name);
            Challenge request = bridge.validate(requestMessage ? value : mail.getJSONObject("request"), key, !requestMessage);
            if (!"authenticate".equals(request.kind) || !id.equals(request.id) || desktop(request) == null)
                throw new IllegalArgumentException("Authentication does not match its delivery route.");
            JSONObject tombstones = bridge.read("kde-cancellations.json");
            if (tombstones == null) tombstones = new JSONObject();
            long now = System.currentTimeMillis();
            ArrayList<String> expired = new ArrayList<>();
            Iterator<String> ids = tombstones.keys();
            while (ids.hasNext()) {
                String previous = ids.next();
                if (tombstones.getJSONObject(previous).getLong("until") < now) expired.add(previous);
            }
            for (String previous : expired) tombstones.remove(previous);
            String tombstoneId = request.payload.getString("machine_id") + ":" + id;
            String requestHash = Bridge.hash(request.bytes);
            if ("cancel.json".equals(name)) {
                if (!bridge.canceled(request, value)) throw new IllegalArgumentException("Invalid signed withdrawal.");
                // The transfer may overtake its request. Remember only verified, recent cancellation.
                long until = request.payload.getLong("expires_at_ms") + 30000;
                if (until > now) {
                    if (tombstones.length() >= 64 && !tombstones.has(tombstoneId))
                        throw new IllegalStateException("Too many pending computer withdrawals.");
                    tombstones.put(tombstoneId, new JSONObject().put("until", until).put("hash", requestHash));
                }
                bridge.write("kde-cancellations.json", tombstones);
                JSONObject current = bridge.read("request.json");
                if (current != null && Arrays.equals(Bridge.decode(current.getString("payload_b64")), request.bytes)) {
                    bridge.write(name, value);
                    RequestReceiver.refreshNotification(context, id, true);
                }
                return;
            }
            if (requestMessage) {
                JSONObject withdrawn = tombstones.optJSONObject(tombstoneId);
                if (withdrawn != null && requestHash.equals(withdrawn.getString("hash"))) return;
                JSONObject old = bridge.read("request.json");
                if (old != null) {
                    try {
                        Challenge previous = bridge.validate(old, key);
                        if (previous.id.equals(id)) {
                            if (!Arrays.equals(previous.bytes, request.bytes)) throw new IllegalArgumentException("Changed request.");
                            return;
                        }
                        JSONObject response = bridge.read("response.json");
                        boolean finished = bridge.canceled(previous) || response != null && previous.id.equals(response.optString("request_id"))
                                && ("declined".equals(response.optString("status")) || bridge.receipt(previous, response));
                        if (!finished) throw new IllegalStateException("Another computer request is active.");
                    } catch (Challenge.Expired ignored) { }
                }
                bridge.write(name, value);
                bridge.write("kde-cancellations.json", tombstones);
                context.getSharedPreferences("kdeconnect", 0).edit().putBoolean("received", true).apply();
                // Receiving through KDE Connect must preserve the user's direct-LAN preference.
                RequestReceiver.refreshNotification(context, id, false);
            } else {
                JSONObject current = bridge.read("request.json");
                JSONObject response = bridge.read("response.json");
                if (current == null || !Arrays.equals(Bridge.decode(current.getString("payload_b64")), request.bytes)
                        || response == null || !id.equals(response.optString("request_id")) || !bridge.receipt(request, response, value))
                    throw new IllegalArgumentException("Confirmation does not match the current approval.");
                bridge.write(name, value);
            }
        }
    }
}
