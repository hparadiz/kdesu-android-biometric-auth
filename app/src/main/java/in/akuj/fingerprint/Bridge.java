package in.akuj.fingerprint;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Base64;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/** Private mailbox shared by the signed LAN transport and development ADB bridge. */
final class Bridge {
    static final Object MAILBOX = new Object();
    private final File directory;
    private final boolean developmentEnrollment;

    Bridge(Context context) {
        directory = context.getFilesDir();
        developmentEnrollment = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    JSONObject read(String name) throws Exception {
        File file = new File(directory, name);
        if (!file.exists()) return null;
        if (file.length() > 65536) throw new IllegalArgumentException("Computer message is too large.");
        return new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
    }

    void write(String name, JSONObject value) throws Exception {
        File temporary = File.createTempFile(name, ".app-tmp", directory);
        Files.write(temporary.toPath(), value.toString().getBytes(StandardCharsets.UTF_8));
        Files.move(temporary.toPath(), new File(directory, name).toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    void identity(SigningKey key) throws Exception {
        write("identity.json", new JSONObject().put("key_id_sha256", key.id)
                .put("public_key_spki_base64", key.publicKeyBase64()));
    }

    Challenge validate(JSONObject envelope, SigningKey key) throws Exception {
        return validate(envelope, key, false);
    }

    Challenge validate(JSONObject envelope, SigningKey key, boolean allowExpired) throws Exception {
        X509Certificate machine = certificate(envelope.getString("machine_certificate_b64"));
        String machineId = hash(machine.getPublicKey().getEncoded());
        JSONObject pairing = pairings().optJSONObject(machineId);
        // Release entry points never bootstrap trust from a request's own certificate.
        if (pairing == null && !developmentEnrollment)
            throw new IllegalArgumentException("Unknown computer. Requests require an enrolled computer key.");
        X509Certificate phone = certificate(envelope.getString("phone_certificate_b64"));
        validateCertificate(machine, machine, true);
        validateCertificate(phone, machine, false);
        verifyEnvelope(envelope, machine);
        Challenge request = new Challenge(envelope, machine, phone, allowExpired);
        if (request.kind.equals("enroll") && !developmentEnrollment)
            throw new IllegalArgumentException("Computer enrollment requires the development ADB bootstrap.");
        if (!Arrays.equals(phone.getPublicKey().getEncoded(), key.publicKey.getEncoded())
                || !key.id.equals(request.payload.getString("phone_key_id"))
                || !machineId.equals(request.payload.getString("machine_id"))
                || !hash(phone.getEncoded()).equals(request.payload.getString("certificate_sha256"))) {
            throw new IllegalArgumentException("Computer request does not match this phone’s key and certificate.");
        }
        if (pairing == null && !request.kind.equals("enroll")) {
            throw new IllegalArgumentException("This phone must be enrolled by the computer first.");
        }
        if (pairing != null) {
            X509Certificate pinned = certificate(pairing.getString("machine_certificate_b64"));
            if (!Arrays.equals(pinned.getPublicKey().getEncoded(), machine.getPublicKey().getEncoded()))
                throw new IllegalArgumentException("Computer identity does not match the stored pairing.");
            if (request.kind.equals("authenticate") && !pairing.getString("phone_certificate_b64")
                    .equals(envelope.getString("phone_certificate_b64"))) {
                throw new IllegalArgumentException("The phone certificate differs from the approved pairing.");
            }
        }
        return request;
    }

    JSONObject signed(Challenge request, byte[] signature) throws Exception {
        if (request.kind.equals("enroll")) {
            JSONObject paired = pairings();
            paired.put(request.payload.getString("machine_id"), new JSONObject()
                    .put("machine_name", request.machineName)
                    .put("machine_certificate_b64", request.envelope.getString("machine_certificate_b64"))
                    .put("phone_certificate_b64", request.envelope.getString("phone_certificate_b64")));
            write("pairings.json", paired);
        }
        JSONObject response = new JSONObject().put("request_id", request.id).put("status", "signed")
                .put("payload_b64", encode(request.bytes)).put("signature_b64", encode(signature))
                .put("phone_certificate_b64", request.envelope.getString("phone_certificate_b64"));
        write("response.json", response);
        return response;
    }

    void declined(Challenge request, String message) throws Exception {
        write("response.json", new JSONObject().put("request_id", request.id)
                .put("status", "declined").put("message", message));
    }

    boolean canceled(Challenge request) throws Exception {
        return canceled(request, read("cancel.json"));
    }

    boolean canceled(Challenge request, JSONObject envelope) throws Exception {
        if (envelope == null) return false;
        JSONObject value = new JSONObject(new String(decode(envelope.getString("payload_b64")), StandardCharsets.UTF_8));
        if (!request.id.equals(value.optString("request_id"))) return false;
        verifyEnvelope(envelope, request.machineCertificate);
        if (!Challenge.DOMAIN.equals(value.getString("domain")) || !"cancel".equals(value.getString("kind"))
                || !request.payload.getString("machine_id").equals(value.getString("machine_id"))
                || !request.payload.getString("phone_key_id").equals(value.getString("phone_key_id"))
                || !hash(request.bytes).equals(value.getString("request_sha256")))
            throw new IllegalArgumentException("Computer cancellation does not match this request.");
        return true;
    }

    boolean receipt(Challenge request, JSONObject response) throws Exception {
        return receipt(request, response, read("receipt.json"));
    }

    boolean receipt(Challenge request, JSONObject response, JSONObject envelope) throws Exception {
        if (envelope == null) return false;
        JSONObject value = new JSONObject(new String(decode(envelope.getString("payload_b64")), StandardCharsets.UTF_8));
        if (!request.id.equals(value.getString("request_id"))) return false;
        verifyEnvelope(envelope, request.machineCertificate);
        if (!Challenge.DOMAIN.equals(value.getString("domain")) || !"receipt".equals(value.getString("kind"))
                || !"approved".equals(value.getString("status"))
                || !request.payload.getString("machine_id").equals(value.getString("machine_id"))
                || !request.payload.getString("phone_key_id").equals(value.getString("phone_key_id"))
                || !hash(decode(response.getString("signature_b64"))).equals(value.getString("response_sha256"))) {
            throw new IllegalArgumentException("Computer confirmation does not match this approval.");
        }
        if (request.execution() && value.optLong("execution_pid", 0) <= 0)
            throw new IllegalArgumentException("The computer did not confirm execution of this command.");
        JSONObject paired = pairings();
        JSONObject computer = paired.optJSONObject(request.payload.getString("machine_id"));
        if (computer != null) {
            computer.put("machine_name", request.machineName);
            write("pairings.json", paired);
        }
        return true;
    }

    void reset() throws Exception {
        for (String name : new String[]{"pairings.json", "pairing.json", "identity.json", "network-identity.json", "request.json", "response.json", "receipt.json", "cancel.json", "kde-cancellations.json"}) {
            Files.deleteIfExists(new File(directory, name).toPath());
        }
    }

    JSONObject pairings() throws Exception {
        JSONObject paired = read("pairings.json");
        if (paired != null) return paired;
        paired = new JSONObject();
        JSONObject legacy = read("pairing.json");
        if (legacy != null) {
            String id = hash(certificate(legacy.getString("machine_certificate_b64")).getPublicKey().getEncoded());
            paired.put(id, legacy);
            write("pairings.json", paired);
        }
        return paired;
    }

    static X509Certificate certificate(String base64) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decode(base64)));
    }

    private static void validateCertificate(X509Certificate cert, X509Certificate root, boolean ca) throws Exception {
        cert.checkValidity();
        cert.verify(root.getPublicKey());
        boolean[] usage = cert.getKeyUsage();
        if (!cert.getIssuerX500Principal().equals(root.getSubjectX500Principal())
                || (cert.getBasicConstraints() >= 0) != ca || usage == null || !usage[0] || usage[5] != ca
                || !"1.2.840.10045.4.3.2".equals(cert.getSigAlgOID())) {
            throw new IllegalArgumentException("Invalid computer or phone certificate.");
        }
    }

    static void verifyEnvelope(JSONObject envelope, X509Certificate certificate) throws Exception {
        Signature verifier = Signature.getInstance(SigningKey.ALGORITHM);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(decode(envelope.getString("payload_b64")));
        if (!verifier.verify(decode(envelope.getString("signature_b64")))) {
            throw new IllegalArgumentException("Computer signature is invalid.");
        }
    }

    static byte[] decode(String value) { return Base64.decode(value, Base64.NO_WRAP); }
    static String encode(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    static String hash(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff));
        }
        return result.toString();
    }
}
