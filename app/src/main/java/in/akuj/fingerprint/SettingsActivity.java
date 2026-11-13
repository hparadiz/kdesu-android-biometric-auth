package in.akuj.fingerprint;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Log;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONObject;
import java.security.Signature;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Desk reader, background availability, KDE Connect setup and key reset. */
public final class SettingsActivity extends Activity {
    /** Returned to MainActivity, which owns the in-memory approval state that a reset must clear. */
    static final int RESULT_RESET = RESULT_FIRST_USER;
    private static final String TAG = "PhoneAuthenticator";
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Bridge bridge;
    private SigningKey key;
    private boolean busy, stopped = true;
    private CancellationSignal networkCancellation;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (stopped) return;
            updateStatus();
            handler.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.settings);
        bridge = new Bridge(this);
        SharedPreferences desk = getSharedPreferences("desk_reader", MODE_PRIVATE);
        Switch deskReader = findViewById(R.id.desk_reader);
        deskReader.setChecked(desk.getBoolean("enabled", false));
        deskReader.setOnCheckedChangeListener((button, enabled) -> desk.edit().putBoolean("enabled", enabled).apply());
        findViewById(R.id.network_toggle).setOnClickListener(v -> toggleNetwork());
        findViewById(R.id.background_setup).setOnClickListener(v ->
                startActivity(new Intent(this, BackgroundSetupActivity.class)));
        findViewById(R.id.kdeconnect_setup).setOnClickListener(v ->
                startActivity(new Intent(this, KdeConnectSetupActivity.class)));
        findViewById(R.id.reset).setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Reset key and all computer pairings?")
                .setMessage("The signing key and all pairings will be deleted. Each computer must approve the new key before you can authenticate again.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Reset", (dialog, which) -> {
                    setResult(RESULT_RESET);
                    finish();
                }).show());
        findViewById(R.id.settings_done).setOnClickListener(v -> finish());
        showRemoteComputers();
        // MainActivity has already created the key; prepare() only opens it here.
        worker.execute(() -> {
            try {
                SigningKey prepared = SigningKey.prepare();
                runOnUiThread(() -> { if (!isDestroyed()) { key = prepared; updateStatus(); } });
            } catch (Exception error) {
                Log.w(TAG, "Signing key unavailable in settings", error);
            }
        });
    }

    @Override protected void onStart() {
        super.onStart();
        stopped = false;
        handler.removeCallbacks(poll);
        handler.post(poll);
    }

    private void updateStatus() {
        boolean received = getSharedPreferences("kdeconnect", 0).getBoolean("received", false);
        ((TextView) findViewById(R.id.kdeconnect_status)).setText(received
                ? "Signed communication is ready" : "Not delivering to Navi yet");
        ((Button) findViewById(R.id.kdeconnect_setup)).setText(received ? "KDE Connect setup instructions" : "Set up KDE Connect");
        ((TextView) findViewById(R.id.network_status)).setText(NetworkService.status);
        ((TextView) findViewById(R.id.background_summary)).setText(BackgroundSetupActivity.summary(this));
        Button toggle = findViewById(R.id.network_toggle);
        toggle.setText(NetworkService.enabled(this) ? "Turn off network authentication" : "Enable network authentication");
        toggle.setEnabled(key != null && !busy);
        findViewById(R.id.background_setup).setEnabled(!busy);
        boolean remote = RemoteChannel.configured(this);
        ((TextView) findViewById(R.id.remote_status)).setText(!remote ? "Off · set up from the computer"
                : NetworkService.remoteStatus.isEmpty() ? "On · background connection not running" : NetworkService.remoteStatus);
        findViewById(R.id.reset).setEnabled(!busy);
    }

    /** One row per computer that may reach this phone over ntfy, each with Turn off. */
    private void showRemoteComputers() {
        android.widget.LinearLayout list = findViewById(R.id.remote_list);
        list.removeAllViews();
        java.util.List<RemoteChannel.Config> configs;
        try { configs = RemoteChannel.configs(this); }
        catch (Exception error) { Log.w(TAG, "Remote approvals unavailable", error); return; }
        for (RemoteChannel.Config config : configs) {
            TextView label = new TextView(this);
            label.setText(config.machineName + " · " + config.host());
            label.setTextColor(getColor(R.color.navi_text));
            label.setTextSize(16);
            label.setPadding(0, 24, 0, 0);
            list.addView(label);
            Button off = new Button(this, null, 0, R.style.SetupButton);
            off.setText("Turn off for " + config.machineName);
            off.setOnClickListener(v -> new AlertDialog.Builder(this)
                    .setTitle("Turn off remote approvals?")
                    .setMessage(config.machineName + " will no longer reach this phone over ntfy. Approvals over KDE Connect "
                            + "keep working. Also turn it off on the computer (Remote Approvals → Turn Off).")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Turn off", (dialog, which) -> {
                        try {
                            RemoteChannel.remove(this, config.machineId);
                            NetworkService.restart(this);
                        } catch (Exception error) { report(error); }
                        showRemoteComputers();
                        updateStatus();
                    }).show());
            list.addView(off);
        }
    }

    private BiometricPrompt.Builder biometricPrompt() {
        BiometricPrompt.Builder builder = new BiometricPrompt.Builder(this);
        if (Build.VERSION.SDK_INT >= 30) builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (Build.VERSION.SDK_INT >= 29) builder.setConfirmationRequired(true);
        return builder;
    }

    private void startNetwork() {
        try {
            startForegroundService(new Intent(this, NetworkService.class));
            updateStatus();
        } catch (Exception error) { report(error); }
    }

    private void toggleNetwork() {
        if (busy || key == null || stopped) return;
        if (NetworkService.enabled(this)) {
            getSharedPreferences("network", 0).edit().putBoolean("enabled", false).apply();
            NetworkService.restart(this); // Remote approvals, if set up, keep running.
            updateStatus();
            return;
        }
        busy = true;
        updateStatus();
        worker.execute(() -> {
            try {
                if (bridge.pairings().length() == 0) throw new IllegalStateException("Pair a computer before enabling network authentication.");
                NetworkIdentity identity = new NetworkIdentity();
                if (identity.approved(bridge, key)) {
                    runOnUiThread(() -> {
                        busy = false;
                        updateStatus();
                        if (!stopped) {
                            getSharedPreferences("network", 0).edit().putBoolean("enabled", true).apply();
                            startNetwork();
                        }
                    });
                    return;
                }
                byte[] statement = identity.statement(key).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                Signature signature = key.beginSignature();
                runOnUiThread(() -> {
                    if (stopped) { busy = false; return; }
                    CancellationSignal cancellation = new CancellationSignal();
                    networkCancellation = cancellation;
                    try {
                        biometricPrompt().setTitle("Enable network authentication")
                                .setSubtitle("Connect your paired computers without debugging")
                                .setDescription("Bind this phone’s encrypted network connection to its approved signing key. Each command will still require a new biometric approval.")
                                .setNegativeButton("Cancel", getMainExecutor(), (dialog, which) -> finishNetworkSetup(cancellation, null))
                                .build().authenticate(new BiometricPrompt.CryptoObject(signature), cancellation,
                                        getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                                    @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                                        if (networkCancellation != cancellation || stopped) return;
                                        try {
                                            Signature authorized = result.getCryptoObject() == null ? null : result.getCryptoObject().getSignature();
                                            if (authorized != signature) throw new IllegalStateException("Network binding was not authorized.");
                                            authorized.update(statement);
                                            byte[] signed = authorized.sign();
                                            if (!key.verify(statement, signed)) throw new IllegalStateException("Network signature did not verify.");
                                            bridge.write("network-identity.json", new JSONObject()
                                                    .put("payload_b64", Bridge.encode(statement)).put("signature_b64", Bridge.encode(signed)));
                                            getSharedPreferences("network", 0).edit().putBoolean("enabled", true).apply();
                                            finishNetworkSetup(cancellation, null);
                                            startNetwork();
                                        } catch (Exception error) { finishNetworkSetup(cancellation, error); }
                                    }
                                    @Override public void onAuthenticationError(int code, CharSequence message) {
                                        finishNetworkSetup(cancellation, null);
                                    }
                                });
                    } catch (Exception error) { finishNetworkSetup(cancellation, error); }
                });
            } catch (Exception error) {
                runOnUiThread(() -> { if (!isDestroyed()) { busy = false; updateStatus(); report(error); } });
            }
        });
    }

    private void finishNetworkSetup(CancellationSignal cancellation, Exception error) {
        if (networkCancellation != cancellation) return;
        networkCancellation = null;
        busy = false;
        updateStatus();
        if (error != null) report(error);
    }

    private void report(Exception error) {
        Log.e(TAG, "Settings error", error);
        String message = error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof KeyPermanentlyInvalidatedException)
                message = "Biometric enrollment or screen lock changed. Reset the key and enroll again on your computer.";
        }
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    @Override protected void onStop() {
        stopped = true;
        handler.removeCallbacks(poll);
        if (networkCancellation != null) {
            CancellationSignal cancellation = networkCancellation;
            networkCancellation = null;
            cancellation.cancel();
            busy = false;
        }
        super.onStop();
    }

    @Override protected void onDestroy() {
        handler.removeCallbacks(poll);
        worker.shutdown();
        super.onDestroy();
    }
}
