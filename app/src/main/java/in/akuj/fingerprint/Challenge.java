package in.akuj.fingerprint;

import android.os.SystemClock;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

/** A machine-signed, operation-bound challenge; the host owns expiry and consumption. */
final class Challenge {
    static final class Expired extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        Expired() { super("The previous computer request expired."); }
    }
    static final String DOMAIN = "android-linux-fingerprint/v1";
    final JSONObject envelope, payload, context;
    final byte[] bytes;
    final String id, kind, operation, machineName;
    final X509Certificate machineCertificate, phoneCertificate;
    final long deadline;

    Challenge(JSONObject envelope, X509Certificate machine, X509Certificate phone, boolean allowExpired) throws Exception {
        this.envelope = envelope;
        bytes = Bridge.decode(envelope.getString("payload_b64"));
        payload = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        id = payload.getString("request_id");
        kind = payload.getString("kind");
        operation = payload.getString("operation");
        machineName = payload.getString("machine_name");
        machineCertificate = machine;
        phoneCertificate = phone;
        context = payload.getJSONObject("context");
        validateText(context.getString("application"), 80, false);
        validateText(context.getString("action_id"), 160, false);
        validateText(context.getString("command"), 512, true);
        validateText(context.getString("requesting_user"), 64, false);
        validateText(context.getString("target_user"), 64, false);
        validateText(context.getString("source"), 64, false);
        validateText(context.optString("icon_name"), 128, true);
        if (context.getLong("requesting_uid") < 0) throw new IllegalArgumentException("Invalid requesting account.");
        validateText(operation, 160, false);
        validateText(machineName, 128, false);
        if ("execute".equals(context.optString("mode"))) {
            JSONObject execution = payload.getJSONObject("execution");
            org.json.JSONArray argv = execution.getJSONArray("argv");
            if (argv.length() != 3 || !"/bin/sh".equals(argv.getString(0)) || !"-c".equals(argv.getString(1))
                    || !context.getString("command").equals(argv.getString(2))
                    || execution.getInt("uid") != 0 || execution.getInt("gid") != 0
                    || !"root".equals(context.getString("target_user")))
                throw new IllegalArgumentException("Execution does not match the displayed command and account.");
            validateText(execution.getString("cwd"), 4096, false);
            if (!execution.getString("cwd").startsWith("/"))
                throw new IllegalArgumentException("Invalid execution directory.");
        }
        long now = System.currentTimeMillis();
        long issued = payload.getLong("issued_at_ms");
        long expires = payload.getLong("expires_at_ms");
        if (!DOMAIN.equals(payload.getString("domain")) || !id.matches("[a-f0-9]{32}")
                || (!kind.equals("enroll") && !kind.equals("authenticate"))
                || operation.length() > 160 || operation.matches("(?s).*[\\x00-\\x1f].*")
                || machineName.length() > 128 || Bridge.decode(payload.getString("nonce")).length != 32
                || issued > now + 30_000 || expires <= issued || expires - issued > 120_000) {
            throw new IllegalArgumentException("Invalid or expired computer request. Start a new request on the computer.");
        }
        if (expires <= now && !allowExpired) throw new Expired();
        deadline = SystemClock.elapsedRealtime() + Math.min(expires - now, 120_000);
    }

    boolean expired() { return SystemClock.elapsedRealtime() >= deadline; }
    boolean notificationOnly() { return "notification-only".equals(context.optString("mode")); }
    boolean execution() { return "execute".equals(context.optString("mode")); }

    private static void validateText(String value, int limit, boolean allowEmpty) {
        if ((!allowEmpty && value.isEmpty()) || value.length() > limit) throw new IllegalArgumentException("Invalid request display metadata.");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c) || (c >= '\u202a' && c <= '\u202e') || (c >= '\u2066' && c <= '\u2069')) {
                throw new IllegalArgumentException("Request metadata contains hidden formatting characters.");
            }
        }
    }
}
