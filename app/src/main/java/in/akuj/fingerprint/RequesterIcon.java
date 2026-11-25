package in.akuj.fingerprint;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import org.json.JSONObject;

/** Decode only bounded thumbnails from the already verified signed context. */
final class RequesterIcon {
    /**
     * The inline icon (cached by hash for later ntfy requests), or, for a request that carries only
     * {@code icon_sha256}, the cached icon with that hash. Null means: show the default icon.
     */
    static Bitmap decode(Context context, JSONObject request) {
        String encoded = request.optString("icon_png_base64");
        byte[] bytes;
        if (!encoded.isEmpty()) {
            if (encoded.length() > 22000) throw new IllegalArgumentException("Requester icon is too large.");
            bytes = Bridge.decode(encoded);
            check(bytes);
            try { IconCache.put(context, Bridge.hash(bytes), bytes); } catch (Exception ignored) { }
        } else {
            bytes = IconCache.get(context, request.optString("icon_sha256"));
            if (bytes == null) return null;
        }
        Bitmap result = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
        if (result == null) throw new IllegalArgumentException("Could not decode the requester icon.");
        return result;
    }

    static void check(byte[] bytes) {
        if (bytes.length < 24 || bytes.length > 16384 || bytes[0] != (byte) 0x89
                || bytes[1] != 'P' || bytes[2] != 'N' || bytes[3] != 'G')
            throw new IllegalArgumentException("Invalid requester PNG icon.");
        BitmapFactory.Options info = new BitmapFactory.Options();
        info.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(bytes, 0, bytes.length, info);
        if (info.outWidth < 1 || info.outHeight < 1 || info.outWidth > 256 || info.outHeight > 256)
            throw new IllegalArgumentException("Requester icon dimensions are invalid.");
    }
}
