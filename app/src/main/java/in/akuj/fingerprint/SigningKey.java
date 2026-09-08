package in.akuj.fingerprint;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.os.Build;
import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

final class SigningKey {
    private static final String ALIAS = "phone-authenticator.biometric-signing.v1";
    static final String ALGORITHM = "SHA256withECDSA";
    final PublicKey publicKey;
    private final PrivateKey privateKey;
    final String id;

    private SigningKey(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff));
        id = hex.toString();
    }

    static synchronized SigningKey prepare() throws Exception {
        KeyStore store = openStore();
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .build());
            generator.generateKeyPair();
        }
        PrivateKey privateKey = (PrivateKey) store.getKey(ALIAS, null);
        KeyInfo info = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo.class);
        if (!isHardwareBacked(info) || !info.isUserAuthenticationRequired()
                || !info.isUserAuthenticationRequirementEnforcedBySecureHardware()) {
            throw new GeneralSecurityException("This device does not provide hardware-enforced biometric signing.");
        }
        return new SigningKey(store.getCertificate(ALIAS).getPublicKey(), privateKey);
    }

    Signature beginSignature() throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        return signature;
    }

    boolean verify(byte[] payload, byte[] signed) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(payload);
        return verifier.verify(signed);
    }

    String publicKeyBase64() { return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP); }

    static synchronized void reset() throws Exception { openStore().deleteEntry(ALIAS); }

    @SuppressWarnings("deprecation") // Android 11 predates getSecurityLevel().
    private static boolean isHardwareBacked(KeyInfo info) {
        if (Build.VERSION.SDK_INT < 31) return info.isInsideSecureHardware();
        int level = info.getSecurityLevel();
        return level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                || level == KeyProperties.SECURITY_LEVEL_STRONGBOX;
    }

    private static KeyStore openStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }
}
