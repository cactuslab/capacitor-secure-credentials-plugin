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
import androidx.annotation.Nullable;
import androidx.biometric.BiometricManager;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL;


public class SecureCredentialsHelper {

    private static final String KEY_ALGORITHM_RSA = "RSA";
    private static final int KEY_LENGTH = 2048;

    private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String TAG = "SecureCredentialsHelper";
    private static final String METADATA_KEY = ".SecureCredentialsHelper";

    private KeyStore ks;

    SecureCredentialsHelper() {
        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            //Use null to load Keystore with default parameters.
            ks.load(null);
        } catch (Exception ex) {
            Log.e(TAG, "We failed to load the keystore. This is unexpected and very bad", ex);
        }
    }

    private String alias(Context context, @NonNull String service, @NonNull String username) {
        return context.getPackageName() + "." + service + "." + username;
    }

    public void createKey(Context context, @NonNull String service, @NonNull String username, @NonNull SecurityStrategyName securityStrategy) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, JSONException {
        String alias = alias(context, service, username);

        if (isKeyAvailable(context, service, username)) {
            try {
                ks.deleteEntry(alias);
            } catch (KeyStoreException e) {
                // Something unexpected happened, we may be able to continue though
                Log.e(TAG, "Unexpected error removing an item from keystore", e);
            }
        }

        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.

        GregorianCalendar start = null;
        GregorianCalendar end = null;
        String[] timezones = TimeZone.getAvailableIDs();
        if (timezones.length > 0) {
            start = new GregorianCalendar(new SimpleTimeZone(0, timezones[0]));
            end = new GregorianCalendar(new SimpleTimeZone(0, timezones[0]));
        } else {
            start = new GregorianCalendar();
            end = new GregorianCalendar();
        }

        // Fix for Huawei P20/30 devices
        start.add(Calendar.DAY_OF_YEAR, -1);

        end.add(Calendar.YEAR, 30);

        BiometricManager biometricManager = BiometricManager.from(context);

        // Specify the parameters object which will be passed to KeyPairGenerator
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                .setKeyValidityStart(start.getTime())
                .setKeyValidityEnd(end.getTime())
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);

        int timeout = 100; // On android 8 this needs to be greater than zero, otherwise the key is not ever unlockable

        switch (securityStrategy) {
            case STANDARD -> {}
            case STANDARD_PLUS_BIO_CHECK -> {}
            case PIN_USER_PRESENCE -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationParameters(timeout, KeyProperties.AUTH_DEVICE_CREDENTIAL);
                } else {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationValidityDurationSeconds(timeout);
                }
            }
            case STRONG_USER_PRESENCE -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationParameters(timeout, KeyProperties.AUTH_BIOMETRIC_STRONG);
                } else {
                    builder.setUserAuthenticationRequired(true);
                    builder.setUserAuthenticationValidityDurationSeconds(timeout);
                }
            }
        }

        AlgorithmParameterSpec spec = builder.build();
        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore. This example uses the AndroidKeyStore.
        KeyPairGenerator kpGenerator;
        kpGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        kpGenerator.initialize(spec);
        // Generate private/public keys
        KeyPair pair = kpGenerator.generateKeyPair();

        Log.i(TAG, "New key created. IsHardwareBacked? " + isKeyHardwareBacked(context, service, username));
        saveMetaData(context, service, username, new MetaData(securityStrategy));
    }

    // Check if device support Hardware-backed keystore
    public boolean isKeyHardwareBacked(Context context, @NonNull String service, @NonNull String username) {
        String alias = alias(context, service, username);
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

    public boolean isKeyAvailable(Context context, @NonNull String service, @NonNull String username) {
        String alias = alias(context, service, username);

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

    private void logBiometricErrorResult(int result, String biometric) {
        switch (result) {
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                    Log.d(TAG, "No " + biometric + " features available on this device.");
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                    Log.d(TAG, biometric + " features are currently unavailable.");
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                    Log.d(TAG, biometric + " on this device haven't been set up");
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                    Log.d(TAG, biometric + " requires a security update");
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED ->
                    Log.d(TAG, biometric + " is not supported on this device");
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN ->
                    Log.d(TAG, biometric + " is presenting an unknown error. Assume it can't be used");
            default -> {}
        }
    }

    public SecurityStrategy[] availableSecurityStrategies(Context context) {
        List<SecurityStrategy> strategies = new ArrayList<>();

        BiometricManager biometricManager = BiometricManager.from(context);
        int strongResult = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (strongResult == BiometricManager.BIOMETRIC_SUCCESS) {
            Log.d(TAG, "App can authenticate using strong biometrics.");
            strategies.add(new SecurityStrategy(SecurityStrategyName.STRONG_USER_PRESENCE, SecurityLevel.L3_USER_PRESENCE, true));
        } else {
            logBiometricErrorResult(strongResult, "Strong Biometric");
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            int deviceCredentialResult = biometricManager.canAuthenticate(DEVICE_CREDENTIAL);
            if (deviceCredentialResult == BiometricManager.BIOMETRIC_SUCCESS) {
                Log.d(TAG, "App can authenticate using device credential.");
                strategies.add(new SecurityStrategy(SecurityStrategyName.PIN_USER_PRESENCE, SecurityLevel.L3_USER_PRESENCE, false));
            } else {
                logBiometricErrorResult(deviceCredentialResult, "Device Credential");
            }
        } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.P || Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
            // TODO: Use KeyguardManager to determine limits
            // KeyguardManager keyguardManager = (KeyguardManager)getSystemService(Activity.KEYGUARD_SERVICE);
            // keyguardManager.isDeviceSecure()
            // Log.v(TAG,""+keyguardManager.inKeyguardRestrictedInputMode());
        }

        int weakResult = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK);
        if (weakResult == BiometricManager.BIOMETRIC_SUCCESS) {
            Log.d(TAG, "App can authenticate using weak biometrics.");
            strategies.add(new SecurityStrategy(SecurityStrategyName.STANDARD_PLUS_BIO_CHECK, SecurityLevel.L1_ENCRYPTED, true));
        } else {
            logBiometricErrorResult(weakResult, "Weak Biometric");
        }

        strategies.add(new SecurityStrategy(SecurityStrategyName.STANDARD, SecurityLevel.L1_ENCRYPTED, false));
        return strategies.toArray(new SecurityStrategy[0]);
    }

    public String[] usernamesForService(Context context, @Nullable String service) {
        if (service == null) {
            return new String[0];
        }
        SharedPreferences preferences = context.getSharedPreferences(service, Context.MODE_PRIVATE);
        return preferences.getAll().keySet().toArray(new String[0]);
    }

    public void removeCredential(Context context, @Nullable String service, @Nullable String username) throws KeyStoreException {
        if (service == null || username == null) {
            return;
        }

        String alias = alias(context, service, username);
        if (isKeyAvailable(context, service, username)) {
            ks.deleteEntry(alias);
        }

        context.getSharedPreferences(service, Context.MODE_PRIVATE).edit().remove(username).apply();
        context.getSharedPreferences(service + METADATA_KEY, Context.MODE_PRIVATE).edit().remove(username).apply();
    }

    public void removeCredentials(Context context, @Nullable String service) throws KeyStoreException {
        if (service == null) {
            return;
        }

        String[] usernames = usernamesForService(context, service);
        for (String username : usernames) {
            String alias = alias(context, service, username);
            if (isKeyAvailable(context, service, username)) {
                ks.deleteEntry(alias);
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            context.deleteSharedPreferences(service);
            context.deleteSharedPreferences(service + METADATA_KEY);
        } else {
            context.getSharedPreferences(service, Context.MODE_PRIVATE).edit().clear().apply();
            context.getSharedPreferences(service + METADATA_KEY, Context.MODE_PRIVATE).edit().clear().apply();
        }
    }

    public void setData(Context context, @NonNull String service, @NonNull String username, @NonNull String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        setData(context, service, username, password.getBytes());
    }

    public void setData(Context context, @NonNull String service, @NonNull String username, @NonNull byte[] data) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        String alias = alias(context, service, username);

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
        editor.apply();
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

    private void saveMetaData(Context context, @NonNull String service, @NonNull String username, @NonNull MetaData data) throws JSONException {
        SharedPreferences pSharedPref = context.getSharedPreferences(service + METADATA_KEY, Context.MODE_PRIVATE);
        if (pSharedPref != null){
            String jsonString = data.asJson().toString();
            SharedPreferences.Editor editor = pSharedPref.edit();
            editor.putString(username, jsonString);
            editor.apply();
        }
    }

    @Nullable
    public MetaData loadMetaData(Context context, @NonNull String service, @NonNull String username) {
        SharedPreferences pSharedPref = context.getSharedPreferences(service + METADATA_KEY, Context.MODE_PRIVATE);
        try{
            if (pSharedPref != null){
                String jsonString = pSharedPref.getString(username, (new JSONObject()).toString());
                JSONObject jsonObject = new JSONObject(jsonString);
                return new MetaData(jsonObject);
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Nullable
    public String getEncryptedData(Context context, String service, String username) {
        SharedPreferences preferences = context.getSharedPreferences(service, Context.MODE_PRIVATE);
        return preferences.getString(username, null);
    }

    @Nullable
    public Cipher makeCipher() {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Nullable
    public Cipher getCipher(PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher;
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Nullable
    public PrivateKey getPrivateKey(Context context, @NonNull String service, @NonNull String username) {
        String alias = alias(context, service, username);
        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            ks.load(null);
            return (PrivateKey) ks.getKey(alias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Nullable
    byte[] decrypt(@Nullable Cipher cipher, @Nullable String encryptedData) throws BadPaddingException, IllegalBlockSizeException {
        if (encryptedData == null || cipher == null)
            return null;
        byte[] encryptedBuffer = Base64.decode(encryptedData, Base64.DEFAULT);

        if (encryptedBuffer.length <= KEY_LENGTH / 8) {
            return cipher.doFinal(encryptedBuffer);
        } else {
            int limit = KEY_LENGTH / 8;
            int position = 0;
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while (position < encryptedBuffer.length) {
                if (encryptedBuffer.length - position < limit)
                    limit = encryptedBuffer.length - position;
                byte[] tmpData = cipher.doFinal(encryptedBuffer, position, limit);
                try {
                    byteArrayOutputStream.write(tmpData);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                position += limit;
            }

            return byteArrayOutputStream.toByteArray();
        }
    }

    @Nullable
    String decryptString(@Nullable Cipher cipher, @Nullable String encryptedData) throws BadPaddingException, IllegalBlockSizeException {
        byte[] data = decrypt(cipher, encryptedData);
        if (data != null) {
            return new String(data);
        }
        return null;
    }


}
