package in.akuj.fingerprint;

import android.content.Context;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Requester icons by SHA-256, so requests sent over ntfy can carry only the signed hash. Icons are
 * stored only after matching a hash from a verified request; at most 128, least recently used first out.
 */
final class IconCache {
    private static final int LIMIT = 128;

    private static File directory(Context context) {
        File directory = new File(context.getFilesDir(), "icons");
        if (!directory.isDirectory() && !directory.mkdirs()) return null;
        return directory;
    }

    static synchronized byte[] get(Context context, String hash) {
        if (!hash.matches("[0-9a-f]{64}")) return null;
        File directory = directory(context);
        if (directory == null) return null;
        File file = new File(directory, hash + ".png");
        try {
            if (!file.isFile() || file.length() > 16384) return null;
            byte[] png = Files.readAllBytes(file.toPath());
            if (!Bridge.hash(png).equals(hash)) {
                file.delete();
                return null;
            }
            file.setLastModified(System.currentTimeMillis());
            return png;
        } catch (Exception error) {
            return null;
        }
    }

    static synchronized void put(Context context, String hash, byte[] png) {
        File directory = directory(context);
        if (directory == null || !hash.matches("[0-9a-f]{64}") || png.length > 16384) return;
        try {
            File file = new File(directory, hash + ".png");
            if (!file.isFile()) {
                File temporary = File.createTempFile("icon", ".tmp", directory);
                Files.write(temporary.toPath(), png);
                if (!temporary.renameTo(file)) temporary.delete();
            }
            file.setLastModified(System.currentTimeMillis());
            File[] icons = directory.listFiles((dir, name) -> name.endsWith(".png"));
            if (icons != null && icons.length > LIMIT) {
                Arrays.sort(icons, Comparator.comparingLong(File::lastModified));
                for (int i = 0; i < icons.length - LIMIT; i++) icons[i].delete();
            }
        } catch (Exception ignored) { /* Cosmetic only. */ }
    }

    static synchronized void clear(Context context) {
        File directory = directory(context);
        File[] icons = directory == null ? null : directory.listFiles();
        if (icons != null) for (File icon : icons) icon.delete();
    }
}
