package in.akuj.fingerprint;

import android.content.Context;
import android.util.Log;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Signed payload bytes inside an envelope, plain ({@code payload_b64}) or compressed
 * ({@code payload_deflate_b64} + {@code payload_dictionary_sha256}).
 *
 * <p>Compressed payloads are raw DEFLATE with a preset dictionary. The dictionaries are committed
 * files packaged as assets ({@code assets/dictionaries/navi-deflate-N.dict}); a payload names its
 * dictionary by SHA-256 and an unknown hash is an error. Signatures always cover the uncompressed
 * bytes, so the dictionary never decides what is trusted.
 */
final class Payloads {
    static final int MAX_PAYLOAD = 131072;
    private static final String TAG = "NaviPayloads";
    private static volatile Map<String, byte[]> dictionaries;

    private Payloads() { }

    /** Loads the packaged dictionaries once; safe to call from every entry point. */
    static void load(Context context) {
        if (dictionaries != null) return;
        synchronized (Payloads.class) {
            if (dictionaries != null) return;
            Map<String, byte[]> known = new HashMap<>();
            try {
                String[] names = context.getAssets().list("dictionaries");
                if (names != null) {
                    for (String name : names) {
                        if (!name.matches("navi-deflate-[1-9][0-9]*\\.dict")) continue;
                        byte[] data = readAsset(context, "dictionaries/" + name, 32768);
                        if (data.length > 0) known.put(Bridge.hash(data), data);
                    }
                }
            } catch (Exception error) {
                Log.e(TAG, "Could not load compression dictionaries", error);
            }
            dictionaries = Collections.unmodifiableMap(known);
        }
    }

    private static byte[] readAsset(Context context, String path, int limit) throws Exception {
        try (InputStream input = context.getAssets().open(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int count; (count = input.read(buffer)) != -1; ) {
                out.write(buffer, 0, count);
                if (out.size() > limit) throw new IllegalArgumentException("Oversized dictionary: " + path);
            }
            return out.toByteArray();
        }
    }

    /** The signed bytes of an envelope. The caller still verifies the signature over them. */
    static byte[] bytes(JSONObject envelope) throws Exception {
        boolean plain = envelope.has("payload_b64"), packed = envelope.has("payload_deflate_b64");
        if (plain == packed) throw new IllegalArgumentException("Invalid envelope.");
        if (plain) {
            if (envelope.has("payload_dictionary_sha256")) throw new IllegalArgumentException("Invalid envelope.");
            return Bridge.decode(envelope.getString("payload_b64"));
        }
        Map<String, byte[]> known = dictionaries;
        byte[] dictionary = known == null ? null : known.get(envelope.optString("payload_dictionary_sha256"));
        if (dictionary == null) throw new IllegalArgumentException("Unknown compression dictionary. Update Navi.");
        return inflate(Bridge.decode(envelope.getString("payload_deflate_b64")), dictionary);
    }

    static byte[] inflate(byte[] data, byte[] dictionary) throws Exception {
        Inflater inflater = new Inflater(true); // raw DEFLATE, as zlib wbits=-15
        try {
            inflater.setDictionary(dictionary);
            inflater.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0 && (inflater.needsInput() || inflater.needsDictionary()))
                    throw new IllegalArgumentException("Invalid compressed payload.");
                out.write(buffer, 0, count);
                if (out.size() > MAX_PAYLOAD) throw new IllegalArgumentException("Compressed payload exceeds its size limit.");
            }
            if (inflater.getRemaining() != 0) throw new IllegalArgumentException("Invalid compressed payload.");
            return out.toByteArray();
        } catch (DataFormatException error) {
            throw new IllegalArgumentException("Invalid compressed payload.");
        } finally {
            inflater.end();
        }
    }

    /**
     * Copies an envelope's payload fields (either form) into {@code target}, so a response echoes the
     * request with the same encoding and dictionary the computer chose.
     */
    static JSONObject copyPayload(JSONObject source, JSONObject target) throws Exception {
        for (String field : new String[]{"payload_b64", "payload_deflate_b64", "payload_dictionary_sha256"}) {
            if (source.has(field)) target.put(field, source.getString(field));
        }
        return target;
    }

    static String utf8(byte[] data) { return new String(data, StandardCharsets.UTF_8); }
}
