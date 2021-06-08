package com.cactuslab.plugins.securecredentials;

import android.content.Intent;

import androidx.activity.result.ActivityResult;
import androidx.annotation.NonNull;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.PluginResult;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@CapacitorPlugin(name = "SecureCredentials")
public class SecureCredentialsPlugin extends Plugin {

    private static final String SERVICE_KEY = "service";
    private static final String USERNAME_KEY = "username";
    private static final String PASSWORD_KEY = "password";
    private static final String OPTIONS_KEY = "options";
    private static final String SECURITY_LEVEL_KEY = "securityLevel";
    private static final String USERNAMES_KEY = "usernames";
    private static final String CREDENTIAL_KEY = "credential";
    private static final String CREDENTIALS_KEY = "credentials";
    private static final String SUCCESS_KEY = "success";

    private SecureCredentialsHelper helper = new SecureCredentialsHelper(getContext());

    @PluginMethod
    public void setCredential(PluginCall call) throws NoSuchAlgorithmException {
        String service = call.getString(SERVICE_KEY);
        String username = call.getString(USERNAME_KEY);
        String password = call.getString(PASSWORD_KEY);
        JSObject options = call.getObject(OPTIONS_KEY, new JSObject());
        assert options != null;

        SecurityLevel securityLevel = SecurityLevel.valueOf(options.getString(SECURITY_LEVEL_KEY, helper.maximumSupportedLevel().level));

        if (service == null || username == null || password == null) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.missingParameters).toJS());
            return;
        }

        try {
            helper.createKey(service, username, securityLevel);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
            e.printStackTrace();
            return;
        }

        try {
            helper.setData(service, username, password);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | InvalidKeyException | InvalidKeySpecException e) {
            call.resolve(SecureCredentialsResult.errorResult(SecureCredentialsError.unknown("error: " + e)).toJS());
            e.printStackTrace();
            return;
        }

        call.resolve(SecureCredentialsResult.successResult.toJS());
    }

    private void startBiometric(final PluginCall call) {

        Intent intent = new Intent(getContext(), AuthActivity.class);

        startActivityForResult(call, intent, "biometricResult");
    }

    @ActivityCallback
    private void biometricResult(PluginCall call, ActivityResult result) {
        if (call == null) {
            return;
        }

        // Do a thing with the result
    }
}
