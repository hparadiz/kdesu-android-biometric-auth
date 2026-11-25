package in.akuj.fingerprint;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Requester icons built into Navi, named by SHA-256 (assets/icons/&lt;sha256&gt;.png). They are committed
 * files rendered by the computer project's `make icons` (Claude, Konsole, Kitty and common generics in
 * each installed icon theme). A request naming one of these hashes needs no PNG; any other icon still
 * arrives inline, or on request over ntfy.
 */
final class BundledIcons {
    private static final Map<String, byte[]> LOADED = new HashMap<>();

    private BundledIcons() { }

    /** The built-in PNG with this hash, or null if Navi does not have it. */
    static synchronized byte[] get(Context context, String hash) {
        if (hash == null || !hash.matches("[0-9a-f]{64}")) return null;
        if (LOADED.containsKey(hash)) return LOADED.get(hash);
        byte[] png = null;
        try (InputStream input = context.getAssets().open("icons/" + hash + ".png")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int count; (count = input.read(buffer)) != -1; ) {
                out.write(buffer, 0, count);
                if (out.size() > 16384) throw new IllegalArgumentException("Oversized bundled icon");
            }
            byte[] data = out.toByteArray();
            if (Bridge.hash(data).equals(hash)) png = data;
        } catch (Exception missing) {
            png = null; // Not built in: the caller falls back to the cache or the computer's copy.
        }
        LOADED.put(hash, png);
        return png;
    }

    /** Built in, or already cached from an earlier request. */
    static byte[] known(Context context, String hash) {
        byte[] png = get(context, hash);
        return png != null ? png : IconCache.get(context, hash);
    }
}
