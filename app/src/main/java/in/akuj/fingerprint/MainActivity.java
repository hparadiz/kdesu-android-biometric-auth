package in.akuj.fingerprint;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationManager;
import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import org.json.JSONObject;
import java.security.Signature;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final String TAG = "PhoneAuthenticator";
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status, detail, challenge, keyInfo;
    private Button authenticate, enroll, reset, proof;
    private Bridge bridge;
    private SigningKey key;
    private Challenge pending, awaiting;
    private JSONObject signedResponse;
    private Attempt active;
    private String seenEnvelope, proofText, openedRequestId;
    private boolean stopped = true, busy, ready;
    private CancellationSignal networkCancellation;
    private final Runnable timeout = () -> cancel("Challenge expired", "Start a fresh request on the computer.");
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (stopped) return;
            updateNetworkStatus();
            if (key != null && !busy) pollComputer();
            offerBackgroundSetup();
            handler.postDelayed(this, 1000);
        }
    };

    private static final class Attempt {
        final Challenge request;
        final CancellationSignal cancellation = new CancellationSignal();
        Signature signature;
        Attempt(Challenge request) { this.request = request; }
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.main);
        bridge = new Bridge(this);
        openedRequestId = getIntent().getStringExtra("request_id");
        RequestReceiver.createChannel(this);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 10);
        }
        status = findViewById(R.id.status);
        detail = findViewById(R.id.detail);
        challenge = findViewById(R.id.challenge);
        keyInfo = findViewById(R.id.key_info);
        authenticate = findViewById(R.id.authenticate);
        enroll = findViewById(R.id.enroll);
        reset = findViewById(R.id.reset);
        proof = findViewById(R.id.proof);
        Button detailsToggle = findViewById(R.id.details_toggle);
        View connectionDetails = findViewById(R.id.connection_details);
        detailsToggle.setOnClickListener(v -> {
            boolean show = connectionDetails.getVisibility() != View.VISIBLE;
            connectionDetails.setVisibility(show ? View.VISIBLE : View.GONE);
            detailsToggle.setText(show ? "Hide connection details" : "Show connection details");
        });
        authenticate.setOnClickListener(v -> {
            if (key == null) loadKey();
            else if (KdeConnectInbox.uses(awaiting)) sendKdeApproval();
            else begin();
        });
        enroll.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_BIOMETRIC_ENROLL)
                .putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BiometricManager.Authenticators.BIOMETRIC_STRONG)));
        reset.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Reset key and all computer pairings?")
                .setMessage("The signing key and all pairings will be deleted. Each computer must approve the new key before you can authenticate again.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Reset", (dialog, which) -> resetKey()).show());
        proof.setOnClickListener(v -> showProof());
        findViewById(R.id.network_toggle).setOnClickListener(v -> toggleNetwork());
        findViewById(R.id.background_setup).setOnClickListener(v ->
                startActivity(new Intent(this, BackgroundSetupActivity.class)));
        findViewById(R.id.kdeconnect_setup).setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Connect through KDE Connect")
                .setMessage("In KDE Connect, open the file-sharing settings and choose a custom destination folder. Select Navi Authenticator from the folder picker’s side menu, then Use this folder.\n\nSigned authentication files go directly to Navi. Other shared files still go to Downloads. Your existing pairing stays in use.")
                .setNegativeButton("Close", null).setPositiveButton("Open KDE Connect", (dialog, which) -> {
                    Intent open = getPackageManager().getLaunchIntentForPackage(KdeConnectInbox.PACKAGE);
                    if (open != null) startActivity(open);
                    else setStatus("KDE Connect unavailable", "Install and pair KDE Connect first.");
                }).show());
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        openedRequestId = intent.getStringExtra("request_id");
        if (openedRequestId != null && (pending == null || !openedRequestId.equals(pending.id))
                && (awaiting == null || !openedRequestId.equals(awaiting.id))) seenEnvelope = null;
        else openedRequestId = null;
    }

    @Override protected void onStart() {
        super.onStart();
        stopped = false;
        if (NetworkService.enabled(this)) startNetwork();
        refresh();
        if (key == null && ready && !busy) loadKey();
        handler.removeCallbacks(poll);
        handler.post(poll);
    }

    private void refresh() {
        int availability = getSystemService(BiometricManager.class)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        ready = availability == BiometricManager.BIOMETRIC_SUCCESS;
        authenticate.setEnabled(ready && !busy && active == null && (key == null || pending != null
                || KdeConnectInbox.uses(awaiting) && !awaiting.expired()));
        authenticate.setText(key == null ? "Prepare phone" : KdeConnectInbox.uses(awaiting) ? "Send approval again" : pending != null && pending.kind.equals("enroll")
                ? "Approve enrollment" : "Approve request");
        enroll.setVisibility(availability == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ? View.VISIBLE : View.GONE);
        reset.setEnabled(active == null && !busy);
        findViewById(R.id.network_toggle).setEnabled(key != null && ready && !busy && active == null);
        findViewById(R.id.background_setup).setEnabled(!busy && active == null);
        if (!ready) setStatus("Biometrics unavailable", availability == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
                ? "Enroll a fingerprint in Android settings, then return here."
                : "Unlock your phone or resolve Android’s biometric availability, then return here.");
    }

    private void loadKey() {
        if (busy || stopped) return;
        busy = true;
        refresh();
        setStatus("Preparing phone…", "Opening your protected signing key.");
        worker.execute(() -> {
            try {
                SigningKey prepared = SigningKey.prepare();
                bridge.identity(prepared);
                JSONObject paired = bridge.pairings();
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    key = prepared;
                    busy = false;
                    keyInfo.setText("Hardware-backed P-256 · biometric approval for every signature\nPhone key: " + key.id);
                    showPairedComputers(paired);
                    setStatus(paired.length() > 0 ? "Waiting for computer" : "Ready for enrollment",
                            paired.length() > 0 ? "Start an authentication request on your computer."
                                    : "Enroll this phone from your computer to approve its public key.");
                    refresh();
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    busy = false;
                    refresh();
                    report(error);
                });
            }
        });
    }

    private void pollComputer() {
        try {
            JSONObject envelope = bridge.read("request.json");
            if (envelope != null && !envelope.toString().equals(seenEnvelope)) {
                cancel("Request replaced", "A new request arrived from the computer.");
                seenEnvelope = envelope.toString();
                pending = null;
                awaiting = null;
                clearProof();
                findViewById(R.id.request_context).setVisibility(View.GONE);
                findViewById(R.id.machine_badge).setVisibility(View.GONE);
                Challenge request = bridge.validate(envelope, key);
                String expected = openedRequestId;
                openedRequestId = null;
                if (expected != null && !expected.equals(request.id))
                    throw new IllegalArgumentException("That notification is no longer current. Open the app again to review the latest request.");
                if (bridge.canceled(request)) {
                    dismissNotification(request);
                    showPairedComputers(bridge.pairings());
                    setStatus("Request withdrawn", "The desktop request has ended.");
                    refresh();
                    return;
                }
                // All displayed authorization context comes from the verified payload.
                Bitmap icon = RequesterIcon.decode(request.context);
                ImageView requester = findViewById(R.id.requester_icon);
                if (icon == null) requester.setImageResource(R.drawable.ic_requester);
                else requester.setImageBitmap(icon);
                requester.setContentDescription(request.context.getString("application") + " icon");
                showMachine(request.machineName, request.payload.getString("machine_id"),
                        request.kind.equals("enroll") ? "New pairing" : "Paired computer");
                ((TextView) findViewById(R.id.application_name)).setText(request.context.getString("application"));
                ((TextView) findViewById(R.id.account_line)).setText(request.context.getString("requesting_user")
                        + " → " + request.context.getString("target_user"));
                String command = request.context.getString("command");
                ((TextView) findViewById(R.id.command_text)).setText(command);
                findViewById(R.id.command_text).setVisibility(command.isEmpty() ? View.GONE : View.VISIBLE);
                findViewById(R.id.command_label).setVisibility(command.isEmpty() ? View.GONE : View.VISIBLE);
                findViewById(R.id.request_context).setVisibility(View.VISIBLE);
                findViewById(R.id.preview_notice).setVisibility(request.notificationOnly() ? View.VISIBLE : View.GONE);
                challenge.setText("REQUEST\n" + request.id + "\nComputer key: "
                        + request.payload.getString("machine_id") + "\nAction: " + request.context.getString("action_id")
                        + "\nRequest source: " + request.context.getString("source")
                        + (request.execution() ? "\nWorking directory: " + request.payload.getJSONObject("execution").getString("cwd") : ""));
                JSONObject previous = bridge.read("response.json");
                if (previous != null && request.id.equals(previous.optString("request_id"))) {
                    if ("signed".equals(previous.optString("status"))) {
                        if (!Arrays.equals(request.bytes, Bridge.decode(previous.getString("payload_b64")))
                                || !key.verify(request.bytes, Bridge.decode(previous.getString("signature_b64")))) {
                            throw new IllegalArgumentException("Saved response does not verify.");
                        }
                        awaiting = request;
                        signedResponse = previous;
                        setStatus("Waiting for computer confirmation", "Your signed approval has been sent.");
                    } else setStatus("Approval stopped", "Start a new request on the computer.");
                } else {
                    pending = request;
                    setStatus(request.kind.equals("enroll") ? "Pair this computer" : "Authentication requested",
                            request.operation);
                }
                refresh();
            }
            if (pending != null && pending.expired()) {
                cancel("Challenge expired", "Start a fresh request on the computer.");
            }
            Challenge current = pending != null ? pending : awaiting;
            if (current != null && bridge.canceled(current)) {
                dismissNotification(current);
                cancel("Request withdrawn", "The desktop request has ended.");
                awaiting = null;
                setStatus("Request withdrawn", "The desktop request has ended.");
            }
            if (awaiting != null) {
                if (bridge.receipt(awaiting, signedResponse)) {
                    proofText = new JSONObject().put("phone_response", signedResponse)
                            .put("computer_receipt", bridge.read("receipt.json")).toString(2);
                    proof.setVisibility(View.VISIBLE);
                    boolean enrolled = awaiting.kind.equals("enroll");
                    dismissNotification(awaiting);
                    showPairedComputers(bridge.pairings());
                    showMachine(awaiting.machineName, awaiting.payload.getString("machine_id"), "Paired computer");
                    setStatus(enrolled ? "Phone approved by computer" : awaiting.execution() ? "Authorized on " + awaiting.machineName : "Phone approval verified",
                            enrolled ? "The computer signed your public key and verified your biometric approval."
                                    : awaiting.execution() ? "Your computer verified this phone’s signature and launched the command you approved."
                                    : awaiting.notificationOnly() ? "Your computer verified the phone’s signature. The desktop still requires its normal authentication."
                                    : "The computer verified your approved certificate and your fresh signed challenge.");
                    Log.i(TAG, (enrolled ? "Enrollment" : "Authentication") + " confirmed by machine; request=" + awaiting.id);
                    awaiting = null;
                    refresh();
                } else if (SystemClock.elapsedRealtime() >= awaiting.deadline + 15000) {
                    awaiting = null;
                    refresh();
                    setStatus("Computer confirmation missing", "The phone signed, but no verified computer confirmation arrived. Start a new request.");
                }
            }
        } catch (Exception error) {
            pending = null;
            awaiting = null;
            refresh();
            try { showPairedComputers(bridge.pairings()); } catch (Exception ignored) { /* Keep the original error. */ }
            if (error instanceof Challenge.Expired)
                setStatus("Waiting for computer", "The previous request expired. Start a new request on your computer.");
            else report(error);
        }
    }

    private void begin() {
        if (active != null || busy || stopped || pending == null) return;
        if (pending.expired()) { cancel("Challenge expired", "Start a fresh request on the computer."); return; }
        Attempt attempt = new Attempt(pending);
        active = attempt;
        clearProof();
        refresh();
        handler.postDelayed(timeout, Math.max(1, pending.deadline - SystemClock.elapsedRealtime()));
        worker.execute(() -> {
            try {
                Signature signature = key.beginSignature();
                runOnUiThread(() -> {
                    if (active != attempt || stopped) return;
                    attempt.signature = signature;
                    prompt(attempt);
                });
            } catch (Exception error) { runOnUiThread(() -> fail(attempt, error)); }
        });
    }

    private void prompt(Attempt attempt) {
        if (attempt.request.expired()) { timeout.run(); return; }
        setStatus("Waiting for your fingerprint", attempt.request.operation);
        try {
            new BiometricPrompt.Builder(this)
                    .setTitle(attempt.request.kind.equals("enroll") ? "Approve computer pairing" : "Approve authentication")
                    .setSubtitle(attempt.request.context.optString("application") + " · " + attempt.request.machineName)
                    .setDescription((attempt.request.notificationOnly() ? "Verification preview. Desktop authentication is separate.\n" : "")
                            + attempt.request.operation + "\nAccount: " + attempt.request.context.optString("target_user")
                            + (attempt.request.context.optString("command").isEmpty() ? "" : "\n" + attempt.request.context.optString("command")))
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(true)
                    .setNegativeButton("Cancel", getMainExecutor(), (dialog, which) -> {
                        declineAttempt(attempt, "Approval canceled", "Start a new request on the computer to try again.");
                    }).build().authenticate(new BiometricPrompt.CryptoObject(attempt.signature),
                    attempt.cancellation, getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) { complete(attempt, result); }
                        @Override public void onAuthenticationFailed() {
                            if (active == attempt) setStatus("Not recognized", "Try your fingerprint again in the Android prompt.");
                        }
                        @Override public void onAuthenticationError(int code, CharSequence message) {
                            declineAttempt(attempt, "Approval stopped", message.toString());
                        }
                    });
        } catch (RuntimeException error) { fail(attempt, error); }
    }

    private void complete(Attempt attempt, BiometricPrompt.AuthenticationResult result) {
        synchronized (Bridge.MAILBOX) { completeLocked(attempt, result); }
    }

    private void completeLocked(Attempt attempt, BiometricPrompt.AuthenticationResult result) {
        if (active != attempt || stopped) return;
        if (attempt.request.expired()) { timeout.run(); return; }
        try {
            if (bridge.canceled(attempt.request)) {
                cancel("Request withdrawn", "The desktop request has ended.");
                return;
            }
            Signature authorized = result.getCryptoObject() == null ? null : result.getCryptoObject().getSignature();
            if (authorized == null || authorized != attempt.signature) throw new IllegalStateException("Signing operation was not authorized.");
            authorized.update(attempt.request.bytes);
            byte[] signed = authorized.sign();
            if (attempt.request.expired()) { timeout.run(); return; }
            if (!key.verify(attempt.request.bytes, signed)) throw new IllegalStateException("Phone signature did not verify.");
            signedResponse = bridge.signed(attempt.request, signed);
            dismissNotification(attempt.request);
            awaiting = attempt.request;
            active = null;
            pending = null;
            handler.removeCallbacks(timeout);
            refresh();
            setStatus("Waiting for computer confirmation", "Your signed approval has been sent.");
            if (KdeConnectInbox.uses(awaiting)) sendKdeApproval();
        } catch (Exception error) { fail(attempt, error); }
    }

    private void sendKdeApproval() {
        if (!KdeConnectInbox.uses(awaiting)) return;
        try { KdeConnectInbox.sendResponse(this, awaiting); }
        catch (Exception error) { setStatus("Approval delivery failed", error.getMessage() + " Tap Send approval again to retry this same signed response."); }
    }

    private void declineAttempt(Attempt attempt, String title, String message) {
        if (active != attempt) return;
        cancel(title, message);
        if (!stopped && KdeConnectInbox.uses(attempt.request)) {
            try { KdeConnectInbox.sendResponse(this, attempt.request); }
            catch (Exception error) { Log.w(TAG, "Could not deliver phone decline", error); }
        }
    }

    private void fail(Attempt attempt, Exception error) {
        if (active != attempt || stopped) return;
        cancel("Approval failed", "No verified approval was sent.");
        report(error);
    }

    private void report(Exception error) {
        Log.e(TAG, "Approval error", error);
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof KeyPermanentlyInvalidatedException) {
                setStatus("Signing key invalidated", "Biometric enrollment or screen lock changed. Reset the key and enroll again on your computer.");
                return;
            }
        }
        setStatus("Unable to approve", error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
    }

    private void cancel(String title, String message) {
        Challenge request = active != null ? active.request : pending;
        if (request == null) return;
        Attempt canceled = active;
        active = null;
        pending = null;
        handler.removeCallbacks(timeout);
        if (canceled != null) canceled.cancellation.cancel();
        dismissNotification(request);
        try { bridge.declined(request, message); } catch (Exception error) { Log.e(TAG, "Could not publish cancellation", error); }
        clearProof();
        refresh();
        setStatus(title, message);
    }

    private void clearProof() { proofText = null; proof.setVisibility(View.GONE); }
    private void setStatus(String title, String message) { status.setText(title); detail.setText(message); }

    private void dismissNotification(Challenge request) {
        getSystemService(NotificationManager.class).cancel(request.id, RequestReceiver.NOTIFICATION_ID);
    }

    private void showMachine(String name, String id, String label) {
        ((TextView) findViewById(R.id.machine_name)).setText(name);
        ((TextView) findViewById(R.id.machine_identity)).setText(label + " · "
                + id.substring(0, 4) + " " + id.substring(4, 8) + " " + id.substring(8, 12));
        ((ImageView) findViewById(R.id.machine_icon)).setColorFilter(Color.HSVToColor(
                new float[]{Integer.parseInt(id.substring(0, 4), 16) * 360f / 65536f, 0.40f, 0.94f}));
        findViewById(R.id.machine_badge).setVisibility(View.VISIBLE);
    }

    private void showPairedComputers(JSONObject paired) {
        int count = paired.length();
        ((TextView) findViewById(R.id.paired_count)).setText(count == 0 ? "No paired computers"
                : count + (count == 1 ? " paired computer" : " paired computers"));
        StringBuilder list = new StringBuilder("PAIRED COMPUTERS");
        java.util.Iterator<String> ids = paired.keys();
        while (ids.hasNext()) {
            String id = ids.next();
            JSONObject value = paired.optJSONObject(id);
            if (value == null || !id.matches("[a-f0-9]{64}")) continue;
            String name = value.optString("machine_name", "Computer");
            list.append("\n").append(name).append(" · ").append(id.substring(0, 12));
            if (count == 1) showMachine(name, id, "Paired computer");
        }
        ((TextView) findViewById(R.id.paired_list)).setText(list.toString());
    }

    private void resetKey() {
        if (active != null || busy) return;
        getSharedPreferences("network", 0).edit().putBoolean("enabled", false).apply();
        stopService(new Intent(this, NetworkService.class));
        cancel("Pairing reset", "Signing identity is being reset.");
        busy = true;
        key = null;
        awaiting = null;
        seenEnvelope = null;
        clearProof();
        findViewById(R.id.request_context).setVisibility(View.GONE);
        findViewById(R.id.machine_badge).setVisibility(View.GONE);
        getSystemService(NotificationManager.class).cancelAll();
        refresh();
        worker.execute(() -> {
            try {
                SigningKey.reset();
                bridge.reset();
                runOnUiThread(() -> { if (!isDestroyed()) { busy = false; loadKey(); } });
            } catch (Exception error) {
                runOnUiThread(() -> { if (!isDestroyed()) { busy = false; refresh(); report(error); } });
            }
        });
    }

    private void showProof() {
        if (proofText == null) return;
        TextView content = new TextView(this);
        content.setText(proofText);
        content.setTextIsSelectable(true);
        content.setTextSize(12);
        content.setPadding(32, 24, 32, 24);
        content.setTypeface(android.graphics.Typeface.MONOSPACE);
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        scroll.addView(content);
        new AlertDialog.Builder(this).setTitle("Signed approval and confirmation")
                .setView(scroll).setPositiveButton("Close", null).show();
    }

    private void updateNetworkStatus() {
        boolean received = getSharedPreferences("kdeconnect", 0).getBoolean("received", false);
        ((TextView) findViewById(R.id.kdeconnect_status)).setText(received
                ? "KDE Connect · signed communication is ready" : "Use your existing KDE Connect pairing");
        ((Button) findViewById(R.id.kdeconnect_setup)).setText(received ? "KDE Connect settings" : "Set up KDE Connect");
        ((TextView) findViewById(R.id.network_status)).setText(NetworkService.status);
        ((TextView) findViewById(R.id.background_summary)).setText(BackgroundSetupActivity.summary(this));
        ((Button) findViewById(R.id.network_toggle)).setText(NetworkService.enabled(this)
                ? "Turn off network authentication" : "Enable network authentication");
    }

    private void offerBackgroundSetup() {
        if (stopped || !hasWindowFocus() || busy || active != null || pending != null || awaiting != null
                || openedRequestId != null || !NetworkService.enabled(this)
                || getSharedPreferences("background", 0).getBoolean("setup_offered_v1", false)) return;
        getSharedPreferences("background", 0).edit().putBoolean("setup_offered_v1", true).apply();
        new AlertDialog.Builder(this).setTitle("Keep Navi available in the background")
                .setMessage("Allow notifications and background battery use so your computers can reach Navi while the screen is locked. A quiet connection notification stays visible while listening. Your enabled connection will restart after reboot and first unlock.")
                .setNegativeButton("Later", null)
                .setPositiveButton("Set up", (dialog, which) -> startActivity(new Intent(this, BackgroundSetupActivity.class))).show();
    }

    private void startNetwork() {
        try {
            startForegroundService(new Intent(this, NetworkService.class));
            updateNetworkStatus();
        } catch (Exception error) { report(error); }
    }

    private void toggleNetwork() {
        if (busy || active != null || key == null || stopped) return;
        if (NetworkService.enabled(this)) {
            getSharedPreferences("network", 0).edit().putBoolean("enabled", false).apply();
            stopService(new Intent(this, NetworkService.class));
            updateNetworkStatus();
            return;
        }
        busy = true;
        refresh();
        worker.execute(() -> {
            try {
                if (bridge.pairings().length() == 0) throw new IllegalStateException("Pair a computer before enabling network authentication.");
                NetworkIdentity identity = new NetworkIdentity();
                if (identity.approved(bridge, key)) {
                    runOnUiThread(() -> {
                        busy = false;
                        refresh();
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
                        new BiometricPrompt.Builder(this).setTitle("Enable network authentication")
                                .setSubtitle("Connect your paired computers without debugging")
                                .setDescription("Bind this phone’s encrypted network connection to its approved signing key. Each command will still require a new biometric approval.")
                                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
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
                runOnUiThread(() -> { if (!isDestroyed()) { busy = false; refresh(); report(error); } });
            }
        });
    }

    private void finishNetworkSetup(CancellationSignal cancellation, Exception error) {
        if (networkCancellation != cancellation) return;
        networkCancellation = null;
        busy = false;
        refresh();
        if (error != null) report(error);
    }

    @Override protected void onStop() {
        stopped = true;
        handler.removeCallbacks(poll);
        if (active != null) cancel("Approval canceled", "The app left the foreground. Start a new computer request.");
        if (networkCancellation != null) {
            CancellationSignal cancellation = networkCancellation;
            networkCancellation = null;
            cancellation.cancel();
            busy = false;
        }
        super.onStop();
    }

    @Override protected void onDestroy() {
        handler.removeCallbacks(timeout);
        handler.removeCallbacks(poll);
        worker.shutdown();
        super.onDestroy();
    }
}
