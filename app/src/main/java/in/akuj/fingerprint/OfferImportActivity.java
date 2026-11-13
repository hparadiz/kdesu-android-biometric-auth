package in.akuj.fingerprint;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

/**
 * "Open with Navi" / "Share to Navi" for a pairing offer that KDE Connect saved to Downloads.
 * Only enroll offers are accepted here; the offer stays untrusted until the user types the code.
 */
public final class OfferImportActivity extends Activity {
    @SuppressWarnings("deprecation") // getParcelableExtra(String) is the only form before Android 13.
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Intent intent = getIntent();
        Uri uri = Intent.ACTION_SEND.equals(intent.getAction())
                ? intent.getParcelableExtra(Intent.EXTRA_STREAM) : intent.getData();
        if (uri == null) {
            finish();
            return;
        }
        new Thread(() -> {
            String error = null;
            try {
                KdeConnectInbox.receiveOfferFile(getApplicationContext(), KdeConnectInbox.readDocument(this, uri));
            } catch (IllegalArgumentException invalid) {
                error = invalid.getMessage();
            } catch (Exception failure) {
                Log.w("PhoneAuthenticator", "Pairing offer import failed", failure);
                error = "This pairing offer could not be used. Start pairing again on the computer.";
            }
            String message = error;
            runOnUiThread(() -> {
                if (message != null) {
                    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                } else {
                    startActivity(new Intent(this, MainActivity.class)
                            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP));
                }
                finish();
            });
        }, "offer-import").start();
    }
}
