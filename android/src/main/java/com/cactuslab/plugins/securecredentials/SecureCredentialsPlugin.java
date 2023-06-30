package com.cactuslab.plugins.securecredentials;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import androidx.activity.result.ActivityResult;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONArray;
import org.json.JSONException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;

@CapacitorPlugin(name = "SecureCredentials")
public class SecureCredentialsPlugin extends Plugin {

    private static final String TAG = "SecureCredentials";

    private static final String SERVICE_KEY = "service";
    private static final String USERNAME_KEY = "username";
    private static final String PASSWORD_KEY = "password";
    private static final String OPTIONS_KEY = "options";
    private static final String CREDENTIAL_KEY = "credential";
    private static final String SECURITY_LEVEL_KEY = "securityLevel";
    private static final String BIO_FACE_KEY = "face";
    private static final String BIO_IRIS_KEY = "iris";
    private static final String BIO_FINGER_KEY = "fingerprint";

    private final SecureCredentialsHelper helper = new SecureCredentialsHelper();

    @PluginMethod
    public void setCredential(PluginCall call) {
        Log.d(TAG, "setCredential");
        String service = call.getString(SERVICE_KEY);
        JSObject credential = call.getObject(CREDENTIAL_KEY);
        String username = credential.getString(USERNAME_KEY);
        String password = credential.getString(PASSWORD_KEY);
        JSObject options = call.getObject(OPTIONS_KEY, new JSObject());
        assert options != null;

        SecurityStrategyName securityStrategy = SecurityStrategyName.get(options.getString(SECURITY_LEVEL_KEY));
        Log.d(TAG, "setCredential for security strategy [" + securityStrategy.name + "]");
        call.resolve(setCredential(service, username, password, securityStrategy).toJS());
    }

    @PluginMethod
    public void getCredential(PluginCall call) {
        Log.d(TAG, "getCredential PluginMethod");
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        assert service != null;
        assert username != null;

        MetaData metaData = helper.loadMetaData(getContext(), service, username);
        PrivateKey key = helper.getPrivateKey(getContext(), service, username);
        String encryptedData = helper.getEncryptedData(getContext(), service, username);
        if (metaData == null || encryptedData == null || key == null || metaData.securityLevel == null) {
            Log.d(TAG, "getCredential Error NoData");
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
            return;
        }

        Log.d(TAG, "getCredential " + metaData.securityLevel.name);
        switch (metaData.securityLevel) {
            case STANDARD -> {
                call.resolve(getCredential(service, username).toJS());
            }
            case STANDARD_PLUS_BIO_CHECK, PIN_USER_PRESENCE, STRONG_USER_PRESENCE -> {
                getActivity().runOnUiThread(() -> startBiometricPrompt(call, service, username, metaData.securityLevel));
            }
            default -> {
                Log.d(TAG, "getCredential Fallthrough. Unexpected security strategy [" + metaData.securityLevel.name + "]");
                call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
            }
        }
    }

    @PluginMethod
    public void getUsernames(PluginCall call) {
        Log.d(TAG, "getUsernames");
        String service = call.getString(SERVICE_KEY);
        String[] accounts = helper.usernamesForService(getContext(), service);
        Log.d(TAG, "getUsernames [" + accounts.toString() + "]");
        call.resolve((new SecureCredentialsResult<>(true, accounts)).toJS());
    }

    @PluginMethod
    public void removeCredential(PluginCall call) {
        Log.d(TAG, "removeCredential");
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        try {
            helper.removeCredential(getContext(), service, username);
            Log.d(TAG, "removeCredential success");
            call.resolve(SecureCredentialsResult.successResult.toJS());
        } catch (KeyStoreException e) {
            Log.e(TAG, "removeCredential error " + e);
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
        }
    }

    @PluginMethod
    public void removeCredentials(PluginCall call) {
        Log.d(TAG, "removeCredentials");
        String service = call.getString(SERVICE_KEY);
        try {
            helper.removeCredentials(getContext(), service);
            call.resolve(SecureCredentialsResult.successResult.toJS());
            Log.d(TAG, "removeCredentials success");
        } catch (KeyStoreException e) {
            Log.e(TAG, "removeCredentials error " + e);
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
        }
    }

    @PluginMethod
    public void availableSecurityStrategies(PluginCall call) {
        SecurityStrategy[] strategyList = helper.availableSecurityStrategies(getContext());
        JSArray array = new JSArray();
        for (SecurityStrategy s: strategyList) {
            array.put(s.toJS());
        }
        call.resolve(new SecureCredentialsResult<>(true, array).toJS());
    }

    @PluginMethod
    public void supportedBiometricSensors(PluginCall call) {
        Log.d(TAG, "supportedBiometricSensors");

        JSObject result = new JSObject();
        PackageManager pm = getContext().getPackageManager();
        result.put(BIO_FINGER_KEY, pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            result.put(BIO_FACE_KEY, pm.hasSystemFeature(PackageManager.FEATURE_FACE));
            result.put(BIO_IRIS_KEY, pm.hasSystemFeature(PackageManager.FEATURE_IRIS));
        } else {
            result.put(BIO_FACE_KEY, false);
            result.put(BIO_IRIS_KEY, false);
        }

        Log.d(TAG, "supportedBiometricSensors " + result.toString());
        call.resolve((new SecureCredentialsResult<>(true, result)).toJS());
    }

    private static final String TITLE_KEY = "title";
    private static final String SUBTITLE_KEY = "subtitle";
    private static final String DESCRIPTION_KEY = "description";
    private static final String NEGATIVE_BUTTON_KEY = "negativeButtonText";

    @MainThread
    private void startBiometricPrompt(final PluginCall call, String service, String username, SecurityStrategyName securityStrategy) {
        SecureCredentialsHelper helper = new SecureCredentialsHelper();
        Context context = getContext();
        String title = call.getString(TITLE_KEY);
        String subtitle = call.getString(SUBTITLE_KEY);
        String description = call.getString(DESCRIPTION_KEY);
        String negativeButtonKey = call.getString(NEGATIVE_BUTTON_KEY);
        MetaData metaData = helper.loadMetaData(context, service, username);

        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title != null ? title : "Authenticate")
                .setSubtitle(subtitle)
                .setDescription(description);

        switch (securityStrategy) {
            case STRONG_USER_PRESENCE -> {
                promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
                promptInfoBuilder.setNegativeButtonText(negativeButtonKey != null ? negativeButtonKey : "Cancel");
            }
            case PIN_USER_PRESENCE -> {
                promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            }
            case STANDARD_PLUS_BIO_CHECK -> {
                promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK);
                promptInfoBuilder.setNegativeButtonText(negativeButtonKey != null ? negativeButtonKey : "Cancel");
            }
            default -> {}
        }

        // TODO: Make this configurable
        promptInfoBuilder.setConfirmationRequired(false);

        BiometricPrompt.PromptInfo promptInfo = promptInfoBuilder.build();
        Executor executor = ContextCompat.getMainExecutor(context);
        BiometricPrompt biometricPrompt = new BiometricPrompt(getActivity(), executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.d(TAG, "biometricResult received CANCELED");
                call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.failedToAccess).toJS());
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                try {
                    PrivateKey key = helper.getPrivateKey(context, service, username);
                    Cipher cipher = helper.getCipher(key);

                    String decryptedString = helper.decryptString(cipher, helper.getEncryptedData(context, service, username));

                    Log.d(TAG, "biometricResult received OK");

                    JSObject credential = new JSObject();
                    credential.put(USERNAME_KEY, call.getString(USERNAME_KEY));
                    credential.put(PASSWORD_KEY, decryptedString);
                    call.resolve((new SecureCredentialsResult<>(true, credential)).toJS());

                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                    Log.d(TAG, "biometricResult received CANCELED");
                    call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.failedToAccess).toJS());
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
//                Log.d(TAG, "biometricResult received CANCELED");
//                call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.failedToAccess).toJS());
            }
        });

        biometricPrompt.authenticate(promptInfo);
////        biometricPrompt.authenticate(promptInfo);
//        PrivateKey key = helper.getPrivateKey(context, service, username);
//        Cipher cipher = helper.getCipher(key);
////        Cipher cipher = helper.makeCipher();
//        if (cipher == null) {
//
//        } else {
//            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
//        }

    }

    public JsAble getCredential(String service, String username) {
        Log.d(TAG, "getCredential for " + username);
        PrivateKey privateKey = helper.getPrivateKey(getContext(), service, username);
        Cipher cipher = helper.getCipher(privateKey);
        String encryptedData = helper.getEncryptedData(getContext(), service, username);
        try {
            String result = helper.decryptString(cipher, encryptedData);
            if (result != null) {
                JSObject credential = new JSObject();
                credential.put(USERNAME_KEY, username);
                credential.put(PASSWORD_KEY, result);
                return (new SecureCredentialsResult<>(true,credential));
            } else {
                return SecureCredentialsResult.errorResult(SecureCredentialsError.noData);
            }
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }
    }

    public JsAble setCredential(String service, String username, String password, SecurityStrategyName securityStrategy) {
        Log.d(TAG, "setCredential for " + username);
        if (service == null || username == null || password == null) {
            return SecureCredentialsResult.errorResult(SecureCredentialsError.missingParameters);
        }

        try {
            helper.createKey(getContext(), service, username, securityStrategy);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | JSONException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }

        try {
            helper.setData(getContext(), service, username, password);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }

        return SecureCredentialsResult.successResult;
    }

}
