package in.akuj.fingerprint;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Context;
import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Pattern;
import org.json.JSONObject;

/** Signed mailbox carried by stock KDE Connect file sharing. */
final class KdeConnectInbox {
    static final String AUTHORITY = "in.akuj.fingerprint.documents";
    static final String PACKAGE = "org.kde.kdeconnect_tp";
    static final int MAX_FILE = 65536;
    /** KDE Connect may append " (1)" when a name already exists in Downloads. */
    private static final Pattern DOWNLOAD_FILE =
            Pattern.compile("navi-auth-(request|receipt|cancel|enroll-offer)-[a-f0-9]{32}( \\(\\d{1,3}\\))?\\.json");

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

    /** Phone key and code tag, returned to the computer that displayed the pairing code. */
    static void sendHello(Activity activity, JSONObject verified) throws Exception {
        String device = verified.getString("desktop_device_id");
        if (!device.matches("[A-Za-z0-9_-]{1,128}")) throw new IllegalArgumentException("Invalid paired computer route.");
        Uri uri = DocumentsContract.buildDocumentUriUsingTree(
                DocumentsContract.buildTreeDocumentUri(AUTHORITY, "navi"), "hello:" + verified.getString("session_id"));
        Intent share = new Intent(Intent.ACTION_SEND)
                .setComponent(new ComponentName(PACKAGE, "org.kde.kdeconnect.plugins.share.ShareActivity"))
                .setType("application/json").putExtra("deviceId", device)
                .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        share.setClipData(ClipData.newRawUri("Pairing confirmation", uri));
        activity.startActivity(share);
    }

    /**
     * A pairing offer the user opened themselves (file picker, "Open with", Share). Only offers are
     * accepted on this path; they stay untrusted until the code shown on the computer is typed.
     */
    static void receiveOfferFile(Context context, byte[] bytes) throws Exception {
        if (bytes.length > MAX_FILE) throw new IllegalArgumentException("This file is too large to be a Navi pairing offer.");
        JSONObject mail;
        try {
            mail = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception error) {
            throw new IllegalArgumentException("This is not a Navi pairing offer.");
        }
        String id = mail.optString("request_id");
        if (!Challenge.DOMAIN.equals(mail.optString("domain")) || !"kdeconnect-mail".equals(mail.optString("kind"))
                || !id.matches("[a-f0-9]{32}") || !"enroll-offer.json".equals(mail.optString("name")))
            throw new IllegalArgumentException("This is not a Navi pairing offer. Choose the navi-auth-enroll-offer file.");
        storeOffer(context, mail, id);
    }

    private static void storeOffer(Context context, JSONObject mail, String id) throws Exception {
        JSONObject offer = mail.getJSONObject("value");
        JSONObject payload = new JSONObject(new String(Bridge.decode(offer.getString("payload_b64")), StandardCharsets.UTF_8));
        if (!id.equals(payload.getString("session_id"))) throw new IllegalArgumentException("Offer does not match its delivery name.");
        PairingCode.receiveOffer(context, offer);
    }

    /** Reads at most MAX_FILE bytes from a picked or shared document. */
    static byte[] readDocument(Context context, Uri uri) throws Exception {
        try (InputStream input = context.getContentResolver().openInputStream(uri)) {
            if (input == null) throw new IllegalArgumentException("The selected file could not be opened.");
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) > 0) {
                output.write(buffer, 0, count);
                if (output.size() > MAX_FILE) throw new IllegalArgumentException("This file is too large to be a Navi pairing offer.");
            }
            return output.toByteArray();
        }
    }

    /**
     * Android 9 and 10 only: KDE Connect saves into Download/ when Navi is not its destination
     * folder. Each recent navi-auth file is processed exactly like a provider delivery, then removed.
     * Android 11+ cannot read other apps' downloads without all-files access, which Navi does not request.
     */
    @SuppressWarnings("deprecation") // getExternalStoragePublicDirectory is the API 28-29 way to reach Download/.
    static int importDownloads(Context context) {
        if (Build.VERSION.SDK_INT > 29
                || context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED)
            return 0;
        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        ArrayList<File> folders = new ArrayList<>();
        folders.add(downloads);
        File[] children = downloads.listFiles(File::isDirectory);
        if (children != null) for (int i = 0; i < children.length && i < 32; i++) folders.add(children[i]);
        SharedPreferences seen = context.getSharedPreferences("download-import", 0);
        long cutoff = System.currentTimeMillis() - 15 * 60_000L;
        ArrayList<File> candidates = new ArrayList<>();
        for (File folder : folders) {
            File[] files = folder.listFiles((dir, name) -> DOWNLOAD_FILE.matcher(name).matches());
            if (files != null) for (File file : files)
                if (file.isFile() && file.length() <= MAX_FILE && file.lastModified() >= cutoff) candidates.add(file);
        }
        // Oldest first, mirroring delivery order (an offer precedes its request; a request its cancel).
        candidates.sort((a, b) -> Long.compare(a.lastModified(), b.lastModified()));
        int imported = 0;
        SharedPreferences.Editor remember = seen.edit();
        for (File file : candidates) {
            String marker = file.getAbsolutePath() + "@" + file.lastModified();
            if (seen.contains(marker)) continue;
            try {
                receive(context, java.nio.file.Files.readAllBytes(file.toPath()));
                imported++;
            } catch (Exception error) {
                Log.w("PhoneAuthenticator", "Ignored " + file.getName() + " from Downloads", error);
            }
            if (!file.delete()) remember.putLong(marker, System.currentTimeMillis());
        }
        for (String marker : seen.getAll().keySet())
            if (seen.getLong(marker, 0) < cutoff) remember.remove(marker);
        remember.apply();
        return imported;
    }

    static void receive(Context context, byte[] bytes) throws Exception {
        if (bytes.length > MAX_FILE) throw new IllegalArgumentException("Authentication file is too large.");
        JSONObject mail = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        String name = mail.getString("name");
        String id = mail.getString("request_id");
        if (!Challenge.DOMAIN.equals(mail.getString("domain")) || !"kdeconnect-mail".equals(mail.getString("kind"))
                || !id.matches("[a-f0-9]{32}")
                || !Arrays.asList("request.json", "receipt.json", "cancel.json", "enroll-offer.json").contains(name))
            throw new IllegalArgumentException("Invalid authentication file.");
        if ("enroll-offer.json".equals(name)) {
            storeOffer(context, mail, id);
            context.getSharedPreferences("kdeconnect", 0).edit().putBoolean("received", true).apply();
            return;
        }
        synchronized (Bridge.MAILBOX) {
            Bridge bridge = new Bridge(context);
            SigningKey key = SigningKey.prepare();
            JSONObject value = mail.getJSONObject("value");
            boolean requestMessage = "request.json".equals(name);
            Challenge request = bridge.validate(requestMessage ? value : mail.getJSONObject("request"), key, !requestMessage);
            // Enrollment is only reachable here after Bridge.validate accepted a code-pinned computer.
            if (!id.equals(request.id) || desktop(request) == null)
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
