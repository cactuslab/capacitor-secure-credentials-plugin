package com.cactuslab.plugins.securecredentials;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyChain;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG;
import static androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL;


public class SecureCredentialsHelper {

    private static final String KEY_ALGORITHM_RSA = "RSA";
    private static final int KEY_LENGTH = 2048;

    private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String TAG = "SecureCredentialsHelper";


    private final Context context;
    private KeyStore ks;

    SecureCredentialsHelper(Context context) {
        this.context = context;
        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            //Use null to load Keystore with default parameters.
            ks.load(null);
        } catch (Exception ex) {
            Log.e(TAG, "We failed to load the keystore. This is unexpected and very bad", ex);
        }
    }

    private String alias(@NonNull String service, @NonNull String username) {
        return context.getPackageName() + "." + service + "." + username;
    }

    public void createKey(@NonNull String service, @NonNull String username, @NonNull SecurityLevel securityLevel) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        String alias = alias(service, username);

        if (isKeyAvailable(service, username)) {
            try {
                ks.deleteEntry(alias);
            } catch (KeyStoreException e) {
                // Something unexpected happened, we may be able to continue though
                Log.e(TAG, "Unexpected error removing an item from keystore", e);
            }
        }

        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 30);

        // Specify the parameters object which will be passed to KeyPairGenerator
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                .setKeyValidityStart(start.getTime())
                .setKeyValidityEnd(end.getTime())
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);

        int timeout = 100; // On android 8 this needs to be greater than zero, otherwise the key is not ever unlockable

        switch (securityLevel) {
            case L1_ENCRYPTED:
            case L2_DEVICE_UNLOCKED:
                break;
            case L3_USER_PRESENCE:
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationParameters(timeout, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
                } else {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationValidityDurationSeconds(timeout);
                }
                break;
            case L4_BIOMETRICS:
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationParameters(timeout, KeyProperties.AUTH_BIOMETRIC_STRONG );
                } else {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationValidityDurationSeconds(timeout);
                }
                break;
        }

        AlgorithmParameterSpec spec = builder.build();
        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore. This example uses the AndroidKeyStore.
        KeyPairGenerator kpGenerator;
        kpGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        kpGenerator.initialize(spec);
        // Generate private/public keys
        kpGenerator.generateKeyPair();

        Log.i(TAG, "New key created. IsHardwareBacked? " + isKeyHardwareBacked(service, username));
    }

    // Check if device support Hardware-backed keystore
    public boolean isKeyHardwareBacked(@NonNull String service, @NonNull String username) {
        String alias = alias(service, username);
        try {
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
            KeyChain.isBoundKeyAlgorithm(KeyProperties.KEY_ALGORITHM_RSA);
            KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo.class);
            boolean isHardwareBackedKeystoreSupported = keyInfo.isInsideSecureHardware();
            Log.d(TAG, "Hardware-Backed Keystore Supported: " + isHardwareBackedKeystoreSupported);
            return isHardwareBackedKeystoreSupported;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeySpecException | NoSuchProviderException e) {
            Log.e(TAG, "Exception trying to inspect if the key is hardware backed", e);
            return false;
        }
    }

    public boolean isKeyAvailable(@NonNull String service, @NonNull String username) {
        String alias = alias(service, username);

        try {
            // Check if Private and Public already keys exists
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
            if (privateKey != null && ks.getCertificate(alias) != null) {
                PublicKey publicKey = ks.getCertificate(alias).getPublicKey();
                if (publicKey != null) {
                    // All keys are available.
                    return true;
                }
            }
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    public SecurityLevel maximumSupportedLevel() {
        BiometricManager biometricManager = BiometricManager.from(context);
        switch (biometricManager.canAuthenticate(BIOMETRIC_STRONG | DEVICE_CREDENTIAL)) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d(TAG, "App can authenticate using biometrics.");
                return SecurityLevel.L4_BIOMETRICS;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.d(TAG, "No biometric features available on this device.");
                break;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.d(TAG, "Biometric features are currently unavailable.");
                break;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                Log.d(TAG, "Biometrics on this device haven't been set up");
                break;
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                Log.d(TAG, "Biometrics requires a security update");
                break;
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                Log.d(TAG, "Biometrics is not supported on this device");
                break;
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                Log.d(TAG, "Biometrics is presenting an unknown error. Assume it can't be used");
                break;
        }
        if (biometricManager.canAuthenticate(DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS) {
            return SecurityLevel.L2_DEVICE_UNLOCKED;
        }
        return SecurityLevel.L1_ENCRYPTED;
    }

    public void setData(@NonNull String service, @NonNull String username, @NonNull String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        setData(service, username, password.getBytes());
    }

    @SuppressLint("ApplySharedPref")
    public void setData(@NonNull String service, @NonNull String username, @NonNull byte[] data) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        String alias = alias(service, username);

        ks.load(null);
        if (ks.getCertificate(alias) == null) return;

        PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

        if (publicKey == null) {
            Log.d(TAG, "Error: Public key was not found in Keystore");
            return;
        }

        String value = encrypt(publicKey, data);

        SharedPreferences preferences = context.getSharedPreferences(service, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        editor.putString(username, value);
        editor.commit();
    }

    @SuppressLint("TrulyRandom")
    private static String encrypt(@NonNull PublicKey encryptionKey, @NonNull byte[] data) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException, InvalidKeySpecException {

        if (data.length <= KEY_LENGTH / 8 - 11) {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            byte[] encrypted = cipher.doFinal(data);
            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        } else {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            int limit = KEY_LENGTH / 8 - 11;
            int position = 0;
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while (position < data.length) {
                if (data.length - position < limit)
                    limit = data.length - position;
                byte[] tmpData = cipher.doFinal(data, position, limit);
                try {
                    byteArrayOutputStream.write(tmpData);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                position += limit;
            }

            return Base64.encodeToString(byteArrayOutputStream.toByteArray(), Base64.DEFAULT);
        }
    }

}
