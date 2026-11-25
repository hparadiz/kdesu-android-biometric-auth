package in.akuj.fingerprint;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Lists the computers this phone is paired with and explains how to pair another one. */
public final class PairedComputersActivity extends Activity {
    private static final int PICK_OFFER = 21;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.paired_computers);
        findViewById(R.id.pair_kdeconnect).setOnClickListener(v ->
                startActivity(new Intent(this, KdeConnectSetupActivity.class)));
        findViewById(R.id.pair_open_offer).setOnClickListener(v -> {
            try {
                startActivityForResult(KdeConnectInbox.offerPicker(), PICK_OFFER);
            } catch (ActivityNotFoundException missing) {
                showStatus("File picker unavailable. Open the navi-auth-enroll-offer file from KDE Connect's notification instead.");
            }
        });
        findViewById(R.id.computers_done).setOnClickListener(v -> finish());
    }

    @Override protected void onResume() {
        super.onResume();
        worker.execute(() -> {
            JSONObject paired;
            try {
                paired = new Bridge(getApplicationContext()).pairings();
            } catch (Exception error) {
                Log.w("PhoneAuthenticator", "Paired computers unavailable", error);
                paired = new JSONObject();
            }
            JSONObject shown = paired;
            runOnUiThread(() -> { if (!isDestroyed()) showComputers(shown); });
        });
    }

    private void showComputers(JSONObject paired) {
        LinearLayout list = findViewById(R.id.computers_list);
        list.removeAllViews();
        LayoutInflater inflater = getLayoutInflater();
        int shown = 0;
        for (Iterator<String> ids = paired.keys(); ids.hasNext(); ) {
            String id = ids.next();
            JSONObject value = paired.optJSONObject(id);
            if (value == null || !id.matches("[a-f0-9]{64}")) continue;
            View row = inflater.inflate(R.layout.computer_row, list, false);
            ((TextView) row.findViewById(R.id.computer_name)).setText(value.optString("machine_name", "Computer"));
            ((TextView) row.findViewById(R.id.computer_identity)).setText(MainActivity.groupedId(id));
            ((ImageView) row.findViewById(R.id.computer_icon)).setColorFilter(MainActivity.machineTint(id));
            list.addView(row);
            shown++;
        }
        findViewById(R.id.computers_empty).setVisibility(shown == 0 ? View.VISIBLE : View.GONE);
    }

    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code != PICK_OFFER || result != RESULT_OK || data == null || data.getData() == null) return;
        android.net.Uri uri = data.getData();
        worker.execute(() -> {
            KdeConnectInbox.ImportResult imported = KdeConnectInbox.importOffer(this, uri);
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                switch (imported.kind) {
                    case ACCEPTED:
                        startActivity(new Intent(this, MainActivity.class)
                                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP));
                        finish();
                        break;
                    case NEEDS_SETUP:
                        findViewById(R.id.pair_status).setVisibility(View.GONE);
                        startActivity(KdeConnectSetupActivity.forOffer(this, imported.machineName));
                        break;
                    default:
                        showStatus(imported.message);
                }
            });
        });
    }

    private void showStatus(String message) {
        TextView status = findViewById(R.id.pair_status);
        status.setText(message);
        status.setVisibility(View.VISIBLE);
    }

    @Override protected void onDestroy() {
        worker.shutdown();
        super.onDestroy();
    }
}
