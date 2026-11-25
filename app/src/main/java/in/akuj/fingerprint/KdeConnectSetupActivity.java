package in.akuj.fingerprint;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;
import android.widget.Button;
import android.widget.TextView;

/**
 * How to make KDE Connect deliver Navi's files to Navi. Opened from Settings, from Paired computers,
 * and whenever a pairing offer arrives through Downloads where Navi could not follow the rest of the
 * enrollment (Android 11+, or Android 9-10 without storage access).
 */
public final class KdeConnectSetupActivity extends Activity {
    private static final String EXTRA_MACHINE = "machine_name";
    private static final int DOWNLOADS_PERMISSION = 22;
    private String machine;

    /** The setup screen after a valid offer from {@code machineName} was found in Downloads. */
    static Intent forOffer(Context context, String machineName) {
        return new Intent(context, KdeConnectSetupActivity.class).putExtra(EXTRA_MACHINE, machineName);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.kdeconnect_setup);
        machine = getIntent().getStringExtra(EXTRA_MACHINE);
        boolean sharingSupported = getResources().getBoolean(R.bool.kdeconnect_sharing_supported);
        boolean downloads = Build.VERSION.SDK_INT <= 29;
        findViewById(R.id.setup_destination).setVisibility(sharingSupported ? View.VISIBLE : View.GONE);
        findViewById(R.id.setup_downloads).setVisibility(downloads ? View.VISIBLE : View.GONE);
        if (!sharingSupported) ((TextView) findViewById(R.id.setup_downloads_heading)).setText("Read messages from Downloads");
        if (machine != null) {
            ((TextView) findViewById(R.id.setup_title)).setText("Finish KDE Connect setup");
            ((TextView) findViewById(R.id.setup_intro)).setText("Navi found the pairing offer from " + machine
                    + " in Downloads, so KDE Connect isn't delivering to Navi yet. The rest of the pairing would be lost "
                    + "the same way, so finish this setup first.");
        } else {
            ((TextView) findViewById(R.id.setup_intro)).setText("Your computer reaches Navi through your existing "
                    + "KDE Connect pairing: pairing offers and approval requests arrive as small signed files. "
                    + "KDE Connect needs to hand those files to Navi."
                    + (getSharedPreferences("kdeconnect", 0).getBoolean("received", false)
                    ? "\n\nKDE Connect is already delivering to Navi." : ""));
        }
        findViewById(R.id.setup_open_kdeconnect).setOnClickListener(v -> {
            Intent open = getPackageManager().getLaunchIntentForPackage(KdeConnectInbox.PACKAGE);
            if (open != null) startActivity(open);
            else Toast.makeText(this, "Install and pair KDE Connect first.", Toast.LENGTH_LONG).show();
        });
        findViewById(R.id.setup_downloads_allow).setOnClickListener(v -> requestPermissions(new String[]{
                Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, DOWNLOADS_PERMISSION));
        findViewById(R.id.setup_done).setOnClickListener(v -> {
            if (machine != null) startActivity(new Intent(this, MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP));
            finish();
        });
    }

    @Override protected void onResume() {
        super.onResume();
        update();
    }

    @Override public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(code, permissions, results);
        if (code == DOWNLOADS_PERMISSION) update();
    }

    private void update() {
        boolean following = KdeConnectInbox.canFollowFromDownloads(this);
        if (Build.VERSION.SDK_INT <= 29) {
            ((TextView) findViewById(R.id.setup_downloads_status)).setText(following
                    ? "Allowed · Navi reads its messages from Downloads while it is open"
                    : "Not allowed yet");
            Button allow = findViewById(R.id.setup_downloads_allow);
            allow.setVisibility(following ? View.GONE : View.VISIBLE);
        }
        String computer = machine != null ? machine : "the computer";
        String footer;
        if (machine != null && following) {
            footer = "Return to Navi: it picks up the offer from Downloads and shows the code box. If the offer has "
                    + "expired, press Enroll again on " + computer + ".";
        } else if (machine != null) {
            footer = "Press Enroll again on " + computer + ". A code box appears in Navi; type the code shown on the computer.";
        } else {
            footer = "Start pairing on your computer: System Settings → Navi Authenticator, choose this phone and press "
                    + "Enroll. A code box appears in Navi; type the code shown on the computer.";
        }
        ((TextView) findViewById(R.id.setup_footer)).setText(footer);
    }
}
