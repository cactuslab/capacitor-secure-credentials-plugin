package com.cactuslab.plugins.securecredentials;

import android.content.Intent;
import android.util.Log;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

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

        SecurityLevel securityLevel = SecurityLevel.get(options.getInteger(SECURITY_LEVEL_KEY, helper.maximumSupportedLevel(getContext()).value));
        Log.d(TAG, "setCredential for security level [" + securityLevel.value + "]");
        call.resolve(setCredential(service, username, password, securityLevel).toJS());
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
        if (metaData == null || encryptedData == null || key == null) {
            Log.d(TAG, "getCredential Error NoData");
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
            return;
        }

        switch (metaData.securityLevel) {
            case L1_ENCRYPTED:
            case L2_DEVICE_UNLOCKED:
                Log.d(TAG, "getCredential L1, L2");
                call.resolve(getCredential(service, username).toJS());
                break;
            case L3_USER_PRESENCE:
            case L4_BIOMETRICS:
                Log.d(TAG, "getCredential L3, L4");
                startBiometric(call, service, username);
                break;
            default:
                Log.d(TAG, "getCredential Fallthrough. Unexpected security level [" + metaData.securityLevel.value + "]");
                call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
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
    public void maximumSecurityLevel(PluginCall call) {
        Log.d(TAG, "maximumSecurityLevel");
        SecurityLevel max = helper.maximumSupportedLevel(getContext());
        Log.d(TAG, "maximumSecurityLevel " + max.value);
        call.resolve((new SecureCredentialsResult<>(true, max.value)).toJS());
    }

    private void startBiometric(final PluginCall call, String service, String username) {
        Log.d(TAG, "startBiometric for user [" + username + "]");
        Intent intent = new Intent(getContext(), AuthActivity.class);
        intent.putExtra(AuthActivity.SERVICE_KEY, service);
        intent.putExtra(AuthActivity.USERNAME_KEY, username);

        String title = call.getString(AuthActivity.TITLE_KEY);
        if (title != null) {
            intent.putExtra(AuthActivity.TITLE_KEY, title);
        }

        String subtitle = call.getString(AuthActivity.SUBTITLE_KEY);
        if (subtitle != null) {
            intent.putExtra(AuthActivity.SUBTITLE_KEY, subtitle);
        }

        String description = call.getString(AuthActivity.DESCRIPTION_KEY);
        if (description != null) {
            intent.putExtra(AuthActivity.DESCRIPTION_KEY, description);
        }

        String negativeButtonKey = call.getString(AuthActivity.NEGATIVE_BUTTON_KEY);
        if (negativeButtonKey != null) {
            intent.putExtra(AuthActivity.NEGATIVE_BUTTON_KEY, negativeButtonKey);
        }

        startActivityForResult(call, intent, "biometricResult");
    }

    @ActivityCallback
    private void biometricResult(PluginCall call, ActivityResult result) {
        if (call == null) {
            return;
        }

        if (result.getResultCode() == RESULT_OK && result.getData() != null) {
            Log.d(TAG, "biometricResult received OK");
            String data = result.getData().getStringExtra("result");
            JSObject credential = new JSObject();
            credential.put(USERNAME_KEY, call.getString(USERNAME_KEY));
            credential.put(PASSWORD_KEY, data);
            call.resolve((new SecureCredentialsResult<>(true,credential)).toJS());
        } else if (result.getResultCode() == RESULT_CANCELED) {
            Log.d(TAG, "biometricResult received CANCELED");
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.failedToAccess).toJS());
        } else {
            Log.d(TAG, "biometricResult received ERROR");
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("Something unknown went wrong")).toJS());
        }
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

    public JsAble setCredential(String service, String username, String password, SecurityLevel securityLevel) {
        Log.d(TAG, "setCredential for " + username);
        if (service == null || username == null || password == null) {
            return SecureCredentialsResult.errorResult(SecureCredentialsError.missingParameters);
        }

        try {
            helper.createKey(getContext(), service, username, securityLevel);
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
