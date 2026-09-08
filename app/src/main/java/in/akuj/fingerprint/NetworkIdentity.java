package in.akuj.fingerprint;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import org.json.JSONObject;

/** Transport key only. It cannot sign biometric command approvals. */
final class NetworkIdentity {
    private static final String ALIAS = "phone-authenticator.network-tls.v1";
    final X509Certificate certificate;
    private final PrivateKey privateKey;

    NetworkIdentity() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) {
            PrivateKey previous = (PrivateKey) store.getKey(ALIAS, null);
            android.security.keystore.KeyInfo info = java.security.KeyFactory.getInstance("EC", "AndroidKeyStore")
                    .getKeySpec(previous, android.security.keystore.KeyInfo.class);
            // Early development builds omitted TLS's prehashed-signature permission.
            if (!java.util.Arrays.asList(info.getDigests()).contains(KeyProperties.DIGEST_NONE)) store.deleteEntry(ALIAS);
        }
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                    .setCertificateSubject(new X500Principal("CN=Navi Authenticator LAN"))
                    .setCertificateSerialNumber(new BigInteger(128, new SecureRandom()).add(BigInteger.ONE))
                    .setCertificateNotBefore(new Date(System.currentTimeMillis() - 86400000L))
                    .setCertificateNotAfter(new Date(System.currentTimeMillis() + 10L * 365 * 86400000))
                    .build());
            generator.generateKeyPair();
        }
        certificate = (X509Certificate) store.getCertificate(ALIAS);
        privateKey = (PrivateKey) store.getKey(ALIAS, null);
    }

    JSONObject statement(SigningKey key) throws Exception {
        return new JSONObject().put("domain", Challenge.DOMAIN).put("kind", "network-identity")
                .put("phone_key_id", key.id).put("tls_certificate_b64", Bridge.encode(certificate.getEncoded()));
    }

    boolean approved(Bridge bridge, SigningKey key) throws Exception {
        JSONObject value = bridge.read("network-identity.json");
        if (value == null) return false;
        byte[] payload = Bridge.decode(value.getString("payload_b64"));
        JSONObject statement = new JSONObject(new String(payload, java.nio.charset.StandardCharsets.UTF_8));
        return key.verify(payload, Bridge.decode(value.getString("signature_b64")))
                && Challenge.DOMAIN.equals(statement.getString("domain"))
                && "network-identity".equals(statement.getString("kind"))
                && key.id.equals(statement.getString("phone_key_id"))
                && java.util.Arrays.equals(certificate.getEncoded(), Bridge.decode(statement.getString("tls_certificate_b64")));
    }

    SSLContext context() throws Exception {
        X509ExtendedKeyManager manager = new X509ExtendedKeyManager() {
            @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return "EC".equals(type) ? ALIAS : null; }
            @Override public String chooseEngineServerAlias(String type, Principal[] issuers, javax.net.ssl.SSLEngine engine) {
                return "EC".equals(type) ? ALIAS : null;
            }
            @Override public String[] getServerAliases(String type, Principal[] issuers) { return "EC".equals(type) ? new String[]{ALIAS} : null; }
            @Override public X509Certificate[] getCertificateChain(String alias) { return new X509Certificate[]{certificate}; }
            @Override public PrivateKey getPrivateKey(String alias) { return privateKey; }
            @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) { return null; }
            @Override public String[] getClientAliases(String type, Principal[] issuers) { return null; }
        };
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(new KeyManager[]{manager}, null, new SecureRandom());
        return context;
    }
}
