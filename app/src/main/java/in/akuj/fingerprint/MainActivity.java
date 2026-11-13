package in.akuj.fingerprint;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.app.NotificationManager;
import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.Settings;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Switch;
import android.widget.TextView;
import org.json.JSONObject;
import java.security.Signature;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final String TAG = "PhoneAuthenticator";
    private static final int PICK_OFFER = 21, DOWNLOADS_PERMISSION = 22;
    private static final String PAIRING_HELP = "Start on the computer: open System Settings → Navi Authenticator, "
            + "pick this phone and press Enroll (or run host.py enroll in a terminal). The computer shows an "
            + "8-character code, and a code box appears here.\n\nNo code box? KDE Connect saved the offer to "
            + "Downloads instead. Tap Open pairing offer… and choose the navi-auth-enroll-offer-….json file, or tap "
            + "KDE Connect's file notification and open it with Navi.";
    private long lastDownloadScan;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status, detail, challenge, keyInfo;
    private Button authenticate, enroll, reset, proof, pairingConfirm, pairingOpen;
    private EditText pairingCode;
    private View pairingPanel;
    private String shownPairing;
    private boolean pairingBusy;
    private Switch deskReader;
    private SharedPreferences deskSettings;
    private Bridge bridge;
    private SigningKey key;
    private Challenge pending, awaiting;
    private JSONObject signedResponse;
    private Attempt active;
    private String seenEnvelope, proofText, openedRequestId;
    private boolean stopped = true, resumed, busy, ready;
    private CancellationSignal networkCancellation;
    private final Runnable timeout = () -> cancel("Challenge expired", "Start a fresh request on the computer.");
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (stopped) return;
            updateNetworkStatus();
            if (key != null && !busy) pollComputer();
            scanDownloads();
            updatePairing();
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
        deskSettings = getSharedPreferences("desk_reader", MODE_PRIVATE);
        deskReader = findViewById(R.id.desk_reader);
        deskReader.setChecked(deskSettings.getBoolean("enabled", false));
        updateDeskReader();
        deskReader.setOnCheckedChangeListener((button, enabled) -> {
            deskSettings.edit().putBoolean("enabled", enabled).apply();
            updateDeskReader();
        });
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
        enroll.setOnClickListener(v -> {
            Intent settings = Build.VERSION.SDK_INT >= 30 ? new Intent(Settings.ACTION_BIOMETRIC_ENROLL)
                    .putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    : new Intent(Settings.ACTION_FINGERPRINT_ENROLL);
            startActivity(settings);
        });
        reset.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Reset key and all computer pairings?")
                .setMessage("The signing key and all pairings will be deleted. Each computer must approve the new key before you can authenticate again.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Reset", (dialog, which) -> resetKey()).show());
        proof.setOnClickListener(v -> showProof());
        pairingPanel = findViewById(R.id.pairing_panel);
        pairingCode = findViewById(R.id.pairing_code);
        pairingConfirm = findViewById(R.id.pairing_confirm);
        pairingConfirm.setOnClickListener(v -> confirmPairing());
        pairingCode.setOnEditorActionListener((view, action, event) -> { confirmPairing(); return true; });
        pairingOpen = findViewById(R.id.pairing_open);
        pairingOpen.setOnClickListener(v -> openOfferPicker());
        findViewById(R.id.pair_computer).setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Pair a computer")
                .setMessage(PAIRING_HELP)
                .setNegativeButton("Close", null)
                .setPositiveButton("Open pairing offer…", (dialog, which) -> openOfferPicker()).show());
        findViewById(R.id.downloads_allow).setOnClickListener(v -> requestPermissions(new String[]{
                Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, DOWNLOADS_PERMISSION));
        findViewById(R.id.network_toggle).setOnClickListener(v -> toggleNetwork());
        findViewById(R.id.background_setup).setOnClickListener(v ->
                startActivity(new Intent(this, BackgroundSetupActivity.class)));
        findViewById(R.id.kdeconnect_setup).setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Connect through KDE Connect")
                .setMessage("In KDE Connect, open the file-sharing settings and choose a custom destination folder. Select Navi Authenticator from the folder picker’s side menu, then Use this folder.\n\nSigned authentication files go directly to Navi. Other shared files still go to Downloads. Your existing pairing stays in use.\n\nWithout this setting, pairing offers land in Downloads: open the received file with Navi, or use Pair a computer… → Open pairing offer….")
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

    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        updateDownloadsAccess();
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused) {
            lastDownloadScan = 0;
            scanDownloads();
        }
    }

    /** Android 9-10: pick up KDE Connect files saved to Download/ (throttled; runs while Navi is visible). */
    private void scanDownloads() {
        if (Build.VERSION.SDK_INT > 29 || stopped || SystemClock.elapsedRealtime() - lastDownloadScan < 3000) return;
        if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) return;
        lastDownloadScan = SystemClock.elapsedRealtime();
        worker.execute(() -> {
            if (KdeConnectInbox.importDownloads(getApplicationContext()) > 0)
                runOnUiThread(() -> { if (!isDestroyed()) updatePairing(); });
        });
    }

    private void updateDownloadsAccess() {
        boolean needed = Build.VERSION.SDK_INT <= 29
                && checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED;
        findViewById(R.id.downloads_access).setVisibility(needed ? View.VISIBLE : View.GONE);
    }

    @Override public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(code, permissions, results);
        if (code != DOWNLOADS_PERMISSION) return;
        updateDownloadsAccess();
        lastDownloadScan = 0;
        scanDownloads();
    }

    private void openOfferPicker() {
        Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
                .putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/json", "text/plain", "application/octet-stream"})
                .putExtra(DocumentsContract.EXTRA_INITIAL_URI,
                        Uri.parse("content://com.android.externalstorage.documents/document/primary%3ADownload"));
        try {
            startActivityForResult(pick, PICK_OFFER);
        } catch (ActivityNotFoundException missing) {
            setStatus("File picker unavailable", "Open the navi-auth-enroll-offer file from KDE Connect's notification instead.");
        }
    }

    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code != PICK_OFFER || result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        worker.execute(() -> {
            String error = null;
            try {
                KdeConnectInbox.receiveOfferFile(getApplicationContext(), KdeConnectInbox.readDocument(this, uri));
            } catch (IllegalArgumentException invalid) {
                error = invalid.getMessage();
            } catch (Exception failure) {
                Log.w(TAG, "Pairing offer import failed", failure);
                error = "This pairing offer could not be used. Start pairing again on the computer.";
            }
            String message = error;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                if (message != null) setStatus("Pairing offer not accepted", message);
                updatePairing();
                if (message == null && pairingCode.getVisibility() == View.VISIBLE) pairingCode.requestFocus();
            });
        });
    }

    @Override protected void onPause() {
        resumed = false;
        super.onPause();
    }

    private void updateDeskReader() {
        if (deskReader.isChecked()) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    private void maybeAutoStart() {
        // pollComputer has already verified the pairing, signature, expiry and withdrawal.
        // Opening the prompt never authorizes a signature: the same CryptoObject still does.
        if (!deskReader.isChecked() || !resumed || stopped || !hasWindowFocus()
                || !ready || key == null || busy || active != null || networkCancellation != null
                || pending == null || !pending.kind.equals("authenticate") || pending.expired()
                || getSystemService(KeyguardManager.class).isDeviceLocked()
                || pending.id.equals(deskSettings.getString("last_request", null))) return;
        // Persist before prompting so recreation cannot repeatedly reopen a canceled request.
        if (!deskSettings.edit().putString("last_request", pending.id).commit()) {
            setStatus("Tap to approve", "Desk reader could not save this request. Use Approve request.");
            return;
        }
        Log.i(TAG, "Desk reader starting biometric prompt; request=" + pending.id);
        begin();
    }

    @SuppressWarnings("deprecation") // Before Android 11, inspect fingerprint enrollment; CryptoObject enforces signing.
    private int biometricAvailability() {
        if (Build.VERSION.SDK_INT >= 30)
            return getSystemService(BiometricManager.class).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        FingerprintManager fingerprints = getSystemService(FingerprintManager.class);
        if (fingerprints == null || !fingerprints.isHardwareDetected()) return BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
        return fingerprints.hasEnrolledFingerprints() ? BiometricManager.BIOMETRIC_SUCCESS : BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED;
    }

    private BiometricPrompt.Builder biometricPrompt() {
        BiometricPrompt.Builder builder = new BiometricPrompt.Builder(this);
        if (Build.VERSION.SDK_INT >= 30) builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (Build.VERSION.SDK_INT >= 29) builder.setConfirmationRequired(true);
        // Android 9's CryptoObject prompt already requires a per-operation biometric.
        return builder;
    }

    private void refresh() {
        int availability = biometricAvailability();
        ready = availability == BiometricManager.BIOMETRIC_SUCCESS;
        authenticate.setEnabled(ready && !busy && active == null && (key == null || pending != null
                || KdeConnectInbox.uses(awaiting) && !awaiting.expired()));
        authenticate.setText(key == null ? "Prepare phone" : KdeConnectInbox.uses(awaiting) ? "Send approval again" : pending != null && pending.kind.equals("enroll")
                ? "Approve enrollment" : "Approve request");
        enroll.setVisibility(availability == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ? View.VISIBLE : View.GONE);
        reset.setEnabled(active == null && !busy);
        if (pairingConfirm != null) pairingConfirm.setEnabled(key != null && ready && !busy && !pairingBusy && active == null);
        deskReader.setEnabled(active == null && !busy);
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
                                    : "On your computer, start pairing in System Settings → Navi Authenticator (or host.py enroll), then enter the code it shows.");
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
            maybeAutoStart();
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

    /** Shows pending pairing offers (untrusted until the typed code matches) or a verified pairing. */
    private void updatePairing() {
        if (pairingPanel == null) return;
        try {
            JSONObject verified = key == null ? null : PairingCode.verified(bridge);
            JSONObject offer = key == null || verified != null ? null : PairingCode.latestOffer(bridge);
            boolean enrolling = pending != null || awaiting != null || active != null;
            if (verified != null && !enrolling) {
                String id = verified.getString("machine_id");
                ((TextView) findViewById(R.id.pairing_machine)).setText("Code accepted for " + verified.getString("machine_name")
                        + " · " + id.substring(0, 4) + " " + id.substring(4, 8) + " " + id.substring(8, 12)
                        + "\nWaiting for its pairing request. If nothing arrives, send the confirmation again.");
                pairingCode.setVisibility(View.GONE);
                pairingOpen.setVisibility(View.GONE);
                pairingConfirm.setVisibility(View.VISIBLE);
                pairingConfirm.setText("Send confirmation again");
                pairingPanel.setVisibility(View.VISIBLE);
                shownPairing = "verified:" + verified.getString("session_id");
            } else if (offer != null && !enrolling) {
                String session = offer.getString("session_id");
                if (!session.equals(shownPairing)) {
                    String id = offer.getString("machine_id");
                    ((TextView) findViewById(R.id.pairing_machine)).setText(offer.getString("machine_name") + " · "
                            + id.substring(0, 4) + " " + id.substring(4, 8) + " " + id.substring(8, 12)
                            + "\nEnter the 8-character code shown on that computer. Only pair computers you are using right now.");
                    pairingCode.setText("");
                    pairingCode.setVisibility(View.VISIBLE);
                    pairingOpen.setVisibility(View.GONE);
                    pairingConfirm.setVisibility(View.VISIBLE);
                    pairingConfirm.setText("Confirm code");
                    shownPairing = session;
                }
                pairingPanel.setVisibility(View.VISIBLE);
            } else if (key != null && !enrolling && bridge.pairings().length() == 0) {
                // First run: explain that pairing starts on the computer, and offer the Downloads fallback.
                if (!"idle".equals(shownPairing)) {
                    ((TextView) findViewById(R.id.pairing_machine)).setText(PAIRING_HELP);
                    pairingCode.setVisibility(View.GONE);
                    pairingConfirm.setVisibility(View.GONE);
                    pairingOpen.setVisibility(View.VISIBLE);
                    shownPairing = "idle";
                }
                pairingPanel.setVisibility(View.VISIBLE);
            } else {
                pairingPanel.setVisibility(View.GONE);
                shownPairing = null;
            }
        } catch (Exception error) {
            Log.w(TAG, "Pairing state unavailable", error);
            pairingPanel.setVisibility(View.GONE);
        }
    }

    private void confirmPairing() {
        if (key == null || pairingBusy || busy || active != null || stopped) return;
        SigningKey signingKey = key;
        boolean resend = pairingCode.getVisibility() != View.VISIBLE;
        String typed = pairingCode.getText().toString();
        pairingBusy = true;
        refresh();
        worker.execute(() -> {
            try {
                JSONObject verified = resend ? PairingCode.verified(bridge) : PairingCode.confirm(this, typed, signingKey);
                if (verified == null) throw new IllegalStateException("The pairing code expired. Start pairing again on the computer.");
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    pairingBusy = false;
                    refresh();
                    try {
                        showMachine(verified.getString("machine_name"), verified.getString("machine_id"), "New pairing");
                        setStatus("Code accepted", "Sending this phone’s public key to " + verified.getString("machine_name")
                                + ". Approve the pairing request that follows with your fingerprint.");
                        KdeConnectInbox.sendHello(this, verified);
                    } catch (Exception error) { report(error); }
                    shownPairing = null;
                    updatePairing();
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    pairingBusy = false;
                    refresh();
                    shownPairing = null;
                    updatePairing();
                    setStatus("Code not accepted", error.getMessage() == null ? "Try again." : error.getMessage());
                });
            }
        });
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
            biometricPrompt()
                    .setTitle(attempt.request.kind.equals("enroll") ? "Approve computer pairing" : "Approve authentication")
                    .setSubtitle(attempt.request.context.optString("application") + " · " + attempt.request.machineName)
                    .setDescription((attempt.request.notificationOnly() ? "Verification preview. Desktop authentication is separate.\n" : "")
                            + attempt.request.operation + "\nAccount: " + attempt.request.context.optString("target_user")
                            + (attempt.request.context.optString("command").isEmpty() ? "" : "\n" + attempt.request.context.optString("command")))
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
        boolean sharingSupported = getResources().getBoolean(R.bool.kdeconnect_sharing_supported);
        boolean received = getSharedPreferences("kdeconnect", 0).getBoolean("received", false);
        ((TextView) findViewById(R.id.kdeconnect_status)).setText(received
                ? "KDE Connect · signed communication is ready" : "Use your existing KDE Connect pairing");
        findViewById(R.id.kdeconnect_status).setVisibility(sharingSupported ? View.VISIBLE : View.GONE);
        findViewById(R.id.kdeconnect_setup).setVisibility(sharingSupported ? View.VISIBLE : View.GONE);
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
