package in.akuj.fingerprint;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import org.json.JSONObject;

/** Decode only bounded thumbnails from the already verified signed context. */
final class RequesterIcon {
    static Bitmap decode(JSONObject context) {
        String encoded = context.optString("icon_png_base64");
        if (encoded.isEmpty()) return null;
        if (encoded.length() > 22000) throw new IllegalArgumentException("Requester icon is too large.");
        byte[] bytes = Bridge.decode(encoded);
        if (bytes.length < 24 || bytes.length > 16384 || bytes[0] != (byte) 0x89
                || bytes[1] != 'P' || bytes[2] != 'N' || bytes[3] != 'G')
            throw new IllegalArgumentException("Invalid requester PNG icon.");
        BitmapFactory.Options info = new BitmapFactory.Options();
        info.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(bytes, 0, bytes.length, info);
        if (info.outWidth < 1 || info.outHeight < 1 || info.outWidth > 256 || info.outHeight > 256)
            throw new IllegalArgumentException("Requester icon dimensions are invalid.");
        Bitmap result = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
        if (result == null) throw new IllegalArgumentException("Could not decode the requester icon.");
        return result;
    }
}
