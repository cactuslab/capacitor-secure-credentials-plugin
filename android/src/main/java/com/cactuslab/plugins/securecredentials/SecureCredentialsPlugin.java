package com.cactuslab.plugins.securecredentials;

import android.content.Intent;

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

    private static final String SERVICE_KEY = "service";
    private static final String USERNAME_KEY = "username";
    private static final String PASSWORD_KEY = "password";
    private static final String OPTIONS_KEY = "options";
    private static final String SECURITY_LEVEL_KEY = "securityLevel";

    private final SecureCredentialsHelper helper = new SecureCredentialsHelper(getContext());

    @PluginMethod
    public void setCredential(PluginCall call) {
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        String password = call.getString(PASSWORD_KEY);
        JSObject options = call.getObject(OPTIONS_KEY, new JSObject());
        assert options != null;

        SecurityLevel securityLevel = SecurityLevel.valueOf(options.getString(SECURITY_LEVEL_KEY, helper.maximumSupportedLevel().level));

        call.resolve(setCredential(service, username, password, securityLevel).toJS());
    }

    @PluginMethod
    public void getCredential(PluginCall call) {
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        assert service != null;
        assert username != null;

        MetaData metaData = helper.loadMetaData(service, username);
        Cipher cipher = helper.getCipher(service, username);
        String encryptedData = helper.getEncryptedData(service, username);
        if (metaData == null || encryptedData == null || cipher == null) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
            return;
        }

        switch (metaData.securityLevel) {
            case L1_ENCRYPTED:
            case L2_DEVICE_UNLOCKED:
                call.resolve(getCredential(service, username).toJS());
                break;
            case L3_USER_PRESENCE:
            case L4_BIOMETRICS:
                startBiometric(call, service, username);
                break;
            default:
                call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.noData).toJS());
        }
    }

    @PluginMethod
    public void getUsernames(PluginCall call) {
        String service = call.getString(SERVICE_KEY);
        String[] accounts = helper.usernamesForService(service);
        call.resolve((new SecureCredentialsResult<>(true, accounts)).toJS());
    }

    @PluginMethod
    void removeCredential(PluginCall call) {
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        try {
            helper.removeCredential(service, username);
            call.resolve(SecureCredentialsResult.successResult.toJS());
        } catch (KeyStoreException e) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
        }
    }

    @PluginMethod
    void removeCredentials(PluginCall call) {
        String service = call.getString(SERVICE_KEY);
        try {
            helper.removeCredentials(service);
            call.resolve(SecureCredentialsResult.successResult.toJS());
        } catch (KeyStoreException e) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
        }
    }

    @PluginMethod
    void canUseSecurityLevel(PluginCall call) {
        String levelString = call.getString(SECURITY_LEVEL_KEY);
        if (levelString == null) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("Missing parameters")).toJS());
            return;
        }

        SecurityLevel queryLevel = SecurityLevel.valueOf(levelString);
        SecurityLevel max = helper.maximumSupportedLevel();
        if (max.comparisonValue >= queryLevel.comparisonValue) {
            call.resolve(SecureCredentialsResult.successResult.toJS());
        } else {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unavailable("This type is unavailable")).toJS());
        }
    }

    @PluginMethod
    void maximumAllowedSecurityLevel(PluginCall call) {
        SecurityLevel max = helper.maximumSupportedLevel();
        call.resolve((new SecureCredentialsResult<>(true, max.level)).toJS());
    }

    private void startBiometric(final PluginCall call, String service, String username) {
        Intent intent = new Intent(getContext(), AuthActivity.class);
        intent.putExtra(SERVICE_KEY, service);
        intent.putExtra(USERNAME_KEY, username);

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
            String data = result.getData().getStringExtra("result");
            call.resolve((new SecureCredentialsResult<>(true,data)).toJS());
        } else if (result.getResultCode() == RESULT_CANCELED) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.failedToAccess).toJS());
        } else {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("Something unknown went wrong")).toJS());
        }
    }

    public JsAble getCredential(String service, String username) {
        Cipher cipher = helper.getCipher(service, username);
        String encryptedData = helper.getEncryptedData(service, username);
        try {
            String result = helper.decryptString(cipher, encryptedData);
            if (result != null) {
                return (new SecureCredentialsResult<>(true,result));
            } else {
                return SecureCredentialsResult.errorResult(SecureCredentialsError.noData);
            }
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }
    }

    public JsAble setCredential(String service, String username, String password, SecurityLevel securityLevel) {
        if (service == null || username == null || password == null) {
            return SecureCredentialsResult.errorResult(SecureCredentialsError.missingParameters);
        }

        try {
            helper.createKey(service, username, securityLevel);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | JSONException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }

        try {
            helper.setData(service, username, password);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e));
        }

        return SecureCredentialsResult.successResult;
    }

}
