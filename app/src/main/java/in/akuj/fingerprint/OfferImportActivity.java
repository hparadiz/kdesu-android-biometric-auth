package in.akuj.fingerprint;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Toast;

/**
 * "Open with Navi" / "Share to Navi" for a pairing offer that KDE Connect saved to Downloads.
 * Only enroll offers are accepted here; the offer stays untrusted until the user types the code. When
 * Navi could not follow the rest of the enrollment from Downloads, the KDE Connect setup screen opens instead.
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
            KdeConnectInbox.ImportResult result = KdeConnectInbox.importOffer(this, uri);
            runOnUiThread(() -> {
                switch (result.kind) {
                    case ACCEPTED:
                        startActivity(new Intent(this, MainActivity.class)
                                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP));
                        break;
                    case NEEDS_SETUP:
                        startActivity(KdeConnectSetupActivity.forOffer(this, result.machineName));
                        break;
                    default:
                        Toast.makeText(this, result.message, Toast.LENGTH_LONG).show();
                }
                finish();
            });
        }, "offer-import").start();
    }
}
