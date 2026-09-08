package in.akuj.fingerprint;

import android.content.ContentUris;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.Binder;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import android.provider.MediaStore;
import android.util.Log;
import android.webkit.MimeTypeMap;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** A SAF destination for stock KDE Connect. Normal shares retain their Downloads destination. */
public final class AuthDocumentsProvider extends DocumentsProvider {
    private static final String ROOT_ID = "navi";
    private static final String[] DOCUMENT_COLUMNS = {Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
        Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE, Document.COLUMN_FLAGS, Document.COLUMN_LAST_MODIFIED};
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4));
    private final Timer deadlines = new Timer("navi-share-deadlines", true);
    private File inbox;

    @Override public boolean onCreate() {
        inbox = new File(getContext().getFilesDir(), "kde-inbox");
        return inbox.isDirectory() || inbox.mkdir();
    }

    @Override public Cursor queryRoots(String[] projection) {
        String[] columns = projection != null ? projection : new String[]{Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_TITLE, Root.COLUMN_SUMMARY, Root.COLUMN_FLAGS, Root.COLUMN_ICON};
        MatrixCursor result = new MatrixCursor(columns);
        MatrixCursor.RowBuilder row = result.newRow();
        put(row, columns, Root.COLUMN_ROOT_ID, ROOT_ID);
        put(row, columns, Root.COLUMN_DOCUMENT_ID, ROOT_ID);
        put(row, columns, Root.COLUMN_TITLE, "Navi Authenticator");
        put(row, columns, Root.COLUMN_SUMMARY, "Authentication inbox · other files go to Downloads");
        put(row, columns, Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE | Root.FLAG_LOCAL_ONLY | Root.FLAG_SUPPORTS_IS_CHILD);
        put(row, columns, Root.COLUMN_ICON, R.drawable.ic_notification);
        return result;
    }

    @Override public Cursor queryDocument(String id, String[] projection) throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DOCUMENT_COLUMNS);
        document(result, id);
        return result;
    }

    @Override public Cursor queryChildDocuments(String parent, String[] projection, String sortOrder) throws FileNotFoundException {
        if (!ROOT_ID.equals(parent)) throw new FileNotFoundException("Unknown folder");
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DOCUMENT_COLUMNS);
        // Authentication messages are transient and do not clutter the file browser.
        String[] fields = {MediaStore.Downloads._ID};
        long identity = Binder.clearCallingIdentity();
        try (Cursor cursor = getContext().getContentResolver().query(MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                fields, MediaStore.MediaColumns.OWNER_PACKAGE_NAME + "=?", new String[]{getContext().getPackageName()},
                MediaStore.MediaColumns.DATE_ADDED + " DESC")) {
            if (cursor != null) while (cursor.moveToNext()) document(result, "download:" + cursor.getLong(0));
        } finally { Binder.restoreCallingIdentity(identity); }
        return result;
    }

    @Override public boolean isChildDocument(String parent, String child) {
        if (!ROOT_ID.equals(parent)) return false;
        try (Cursor result = queryDocument(child, null)) { return result.getCount() > 0 && !ROOT_ID.equals(child); }
        catch (Exception invalid) { return false; }
    }

    @Override public String createDocument(String parent, String mime, String name) throws FileNotFoundException {
        if (!ROOT_ID.equals(parent) || Document.MIME_TYPE_DIR.equals(mime) || name == null || name.length() > 240
                || name.isEmpty() || name.contains("/") || name.contains("\\") || name.matches("(?s).*[\\x00-\\x1f].*"))
            throw new FileNotFoundException("Choose the Navi Authenticator folder itself");
        long identity = Binder.clearCallingIdentity();
        try {
            if (name.matches("navi-auth-(request|receipt|cancel)-[a-f0-9]{32}\\.json")) {
                File[] files = inbox.listFiles();
                int retained = 0;
                if (files != null) for (File file : files) {
                    if (file.lastModified() < System.currentTimeMillis() - 600000) Files.deleteIfExists(file.toPath());
                    else retained++;
                }
                if (retained >= 192) throw new FileNotFoundException("Authentication inbox is busy");
                String token = UUID.randomUUID().toString();
                Files.write(new File(inbox, token + ".name").toPath(), name.getBytes(StandardCharsets.UTF_8));
                Files.write(new File(inbox, token).toPath(), new byte[0]);
                return "incoming:" + token;
            }
            String extension = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT) : "";
            String guessed = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
            ContentValues values = new ContentValues();
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
            values.put(MediaStore.MediaColumns.MIME_TYPE, guessed != null ? guessed : "application/octet-stream");
            values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/");
            Uri uri = getContext().getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri == null) throw new FileNotFoundException("Could not create shared download");
            return "download:" + ContentUris.parseId(uri);
        } catch (Exception error) { throw missing(error); }
        finally { Binder.restoreCallingIdentity(identity); }
    }

    @Override public ParcelFileDescriptor openDocument(String id, String mode, CancellationSignal signal) throws FileNotFoundException {
        if (id.startsWith("download:")) {
            downloadInfo(id); // Confine this provider to the downloads it created.
            long identity = Binder.clearCallingIdentity();
            try { return getContext().getContentResolver().openFileDescriptor(downloadUri(id), mode, signal); }
            finally { Binder.restoreCallingIdentity(identity); }
        }
        if (id.matches("response:[a-f0-9]{32}")) {
            if (!"r".equals(mode)) throw new FileNotFoundException("Approval is read-only");
            return responsePipe(response(id)); // Snapshot bytes; a replaced mailbox cannot change an open response.
        }
        File file = incoming(id);
        if ("r".equals(mode)) return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
        if (!"w".equals(mode) && !"wt".equals(mode)) throw new FileNotFoundException("Unsupported inbox mode");
        ParcelFileDescriptor[] pipe = null;
        try {
            pipe = ParcelFileDescriptor.createReliablePipe();
            final ParcelFileDescriptor input = pipe[0];
            workers.execute(() -> consume(input, file));
            return pipe[1];
        } catch (Exception error) {
            if (pipe != null) for (ParcelFileDescriptor fd : pipe) try { fd.close(); } catch (Exception ignored) { }
            throw missing(error);
        }
    }

    private ParcelFileDescriptor responsePipe(byte[] bytes) throws FileNotFoundException {
        ParcelFileDescriptor[] pipe = null;
        try {
            pipe = ParcelFileDescriptor.createReliablePipe();
            final ParcelFileDescriptor output = pipe[1];
            workers.execute(() -> {
                TimerTask timeout = new TimerTask() {
                    @Override public void run() { try { output.closeWithError("Approval transfer expired"); } catch (Exception ignored) { } }
                };
                deadlines.schedule(timeout, 15000);
                try (ParcelFileDescriptor.AutoCloseOutputStream stream = new ParcelFileDescriptor.AutoCloseOutputStream(output)) {
                    stream.write(bytes);
                } catch (Exception error) { Log.w("PhoneAuthenticator", "Approval file delivery failed", error); }
                finally { timeout.cancel(); deadlines.purge(); }
            });
            return pipe[0];
        } catch (Exception error) {
            if (pipe != null) for (ParcelFileDescriptor fd : pipe) try { fd.close(); } catch (Exception ignored) { }
            throw missing(error);
        }
    }

    private void consume(ParcelFileDescriptor pipe, File file) {
        TimerTask timeout = new TimerTask() {
            @Override public void run() { try { pipe.closeWithError("Authentication transfer expired"); } catch (Exception ignored) { } }
        };
        deadlines.schedule(timeout, 15000);
        try (ParcelFileDescriptor.AutoCloseInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(pipe)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 65536) throw new IllegalArgumentException("Authentication file is too large");
                output.write(buffer, 0, count);
            }
            pipe.checkError();
            byte[] bytes = output.toByteArray();
            KdeConnectInbox.receive(getContext(), bytes);
            Files.write(file.toPath(), bytes);
            Log.i("PhoneAuthenticator", "Verified KDE Connect inbox delivery");
        } catch (Exception error) {
            Log.w("PhoneAuthenticator", "KDE Connect inbox rejected message", error);
            try { pipe.closeWithError("Invalid authentication message"); } catch (Exception ignored) { }
        } finally { timeout.cancel(); deadlines.purge(); }
    }

    @Override public void deleteDocument(String id) throws FileNotFoundException {
        if (id.startsWith("download:")) {
            downloadInfo(id);
            long identity = Binder.clearCallingIdentity();
            try { getContext().getContentResolver().delete(downloadUri(id), null, null); }
            finally { Binder.restoreCallingIdentity(identity); }
            return;
        }
        try {
            File file = incoming(id);
            Files.deleteIfExists(file.toPath());
            Files.deleteIfExists(new File(inbox, file.getName() + ".name").toPath());
        } catch (Exception error) { throw missing(error); }
    }

    private void document(MatrixCursor cursor, String id) throws FileNotFoundException {
        String name, mime; long size = 0, modified = 0; int flags;
        try {
            if (ROOT_ID.equals(id)) {
                name = "Navi Authenticator"; mime = Document.MIME_TYPE_DIR; flags = Document.FLAG_DIR_SUPPORTS_CREATE;
            } else if (id.startsWith("download:")) {
                JSONObject info = downloadInfo(id);
                name = info.getString("name"); mime = info.getString("mime"); size = info.getLong("size");
                flags = Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_DELETE;
            } else if (id.matches("response:[a-f0-9]{32}")) {
                byte[] bytes = response(id);
                name = "navi-auth-response-" + id.substring(9) + ".json"; mime = "application/json"; size = bytes.length; flags = 0;
            } else {
                File file = incoming(id);
                name = new String(Files.readAllBytes(new File(inbox, file.getName() + ".name").toPath()), StandardCharsets.UTF_8);
                mime = "application/json"; size = file.length(); modified = file.lastModified();
                flags = Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_DELETE;
            }
            MatrixCursor.RowBuilder row = cursor.newRow(); String[] columns = cursor.getColumnNames();
            put(row, columns, Document.COLUMN_DOCUMENT_ID, id); put(row, columns, Document.COLUMN_DISPLAY_NAME, name);
            put(row, columns, Document.COLUMN_MIME_TYPE, mime); put(row, columns, Document.COLUMN_SIZE, size);
            put(row, columns, Document.COLUMN_LAST_MODIFIED, modified); put(row, columns, Document.COLUMN_FLAGS, flags);
        } catch (Exception error) { throw missing(error); }
    }

    private File incoming(String id) throws FileNotFoundException {
        if (!id.matches("incoming:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"))
            throw new FileNotFoundException("Unknown document");
        File file = new File(inbox, id.substring(9));
        if (!file.isFile()) throw new FileNotFoundException("Expired document");
        return file;
    }

    private byte[] response(String id) throws FileNotFoundException {
        try {
            Bridge bridge = new Bridge(getContext());
            JSONObject value = bridge.read("response.json");
            if (value == null || !id.substring(9).equals(value.optString("request_id"))) throw new FileNotFoundException("Expired approval");
            JSONObject request = bridge.read("request.json");
            if (request == null) throw new FileNotFoundException("No current request");
            Challenge challenge = bridge.validate(request, SigningKey.prepare(), true);
            if (!challenge.id.equals(id.substring(9)) || !KdeConnectInbox.uses(challenge) || bridge.canceled(challenge)
                    || challenge.payload.getLong("expires_at_ms") + 30000 < System.currentTimeMillis())
                throw new FileNotFoundException("Approval is no longer available");
            return value.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception error) { throw missing(error); }
    }

    private Uri downloadUri(String id) throws FileNotFoundException {
        if (!id.matches("download:[1-9][0-9]{0,17}")) throw new FileNotFoundException("Unknown download");
        return ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, Long.parseLong(id.substring(9)));
    }

    private JSONObject downloadInfo(String id) throws FileNotFoundException {
        String[] fields = {MediaStore.MediaColumns.DISPLAY_NAME, MediaStore.MediaColumns.MIME_TYPE,
            MediaStore.MediaColumns.SIZE, MediaStore.MediaColumns.OWNER_PACKAGE_NAME};
        long identity = Binder.clearCallingIdentity();
        try (Cursor cursor = getContext().getContentResolver().query(downloadUri(id), fields, null, null, null)) {
            if (cursor == null || !cursor.moveToFirst() || !getContext().getPackageName().equals(cursor.getString(3)))
                throw new FileNotFoundException("Unknown download");
            return new JSONObject().put("name", cursor.getString(0)).put("mime", cursor.getString(1)).put("size", cursor.getLong(2));
        } catch (Exception error) { throw missing(error); }
        finally { Binder.restoreCallingIdentity(identity); }
    }

    private static void put(MatrixCursor.RowBuilder row, String[] columns, String name, Object value) {
        for (String column : columns) if (column.equals(name)) { row.add(name, value); return; }
    }

    private static FileNotFoundException missing(Exception error) {
        return new FileNotFoundException(error.getMessage() == null ? "Document unavailable" : error.getMessage());
    }
}
