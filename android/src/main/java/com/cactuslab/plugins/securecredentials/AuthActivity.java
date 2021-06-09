package com.cactuslab.plugins.securecredentials;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AuthActivity extends AppCompatActivity {

    public static final String SERVICE_KEY = "secureCredentials.SERVICE";
    public static final String USERNAME_KEY = "secureCredentials.USERNAME";

    public static final String TITLE_KEY = "title";
    public static final String SUBTITLE_KEY = "subtitle";
    public static final String DESCRIPTION_KEY = "description";
    public static final String NEGATIVE_BUTTON_KEY = "negativeButtonText";

    private Executor executor;
    private BiometricPrompt.PromptInfo promptInfo;
    private BiometricPrompt biometricPrompt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);

        // Search the intent for the service and username. Use that to get the crypto object to authenticate

        SecureCredentialsHelper helper = new SecureCredentialsHelper(this);
        String service = getIntent().getStringExtra(SERVICE_KEY);
        String username = getIntent().getStringExtra(USERNAME_KEY);

        MetaData metaData = helper.loadMetaData(service, username);

        int allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG;
        if (metaData != null && metaData.securityLevel == SecurityLevel.L3_USER_PRESENCE) {
            allowedAuthenticators = allowedAuthenticators | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        }
        // The successful result will be the decrypted String value
        executor = ContextCompat.getMainExecutor(this);

        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(getIntent().hasExtra(TITLE_KEY) ? getIntent().getStringExtra(TITLE_KEY) : "Authenticate")
                .setSubtitle(getIntent().hasExtra(SUBTITLE_KEY) ? getIntent().getStringExtra(SUBTITLE_KEY) : null)
                .setDescription(getIntent().hasExtra(DESCRIPTION_KEY) ? getIntent().getStringExtra(DESCRIPTION_KEY) : null)
                .setNegativeButtonText(getIntent().hasExtra(NEGATIVE_BUTTON_KEY) ? getIntent().getStringExtra(NEGATIVE_BUTTON_KEY) : "Cancel")
                .setAllowedAuthenticators(allowedAuthenticators)
                .build();

        biometricPrompt = new BiometricPrompt(this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                finishActivity(RESULT_CANCELED,"error");
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                try {
                    Cipher cipher = helper.getCipher(service, username);
                    String decryptedString = helper.decryptString(cipher, helper.getEncryptedData(service, username));
                    finishActivity(RESULT_OK, decryptedString);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                    finishActivity(RESULT_CANCELED, "");
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                finishActivity(RESULT_CANCELED,"failed");
            }
        });

        biometricPrompt.authenticate(promptInfo);
    }

    void finishActivity(int resultCode, String result) {
        Intent intent = new Intent();
        intent.putExtra("result", result);
        setResult(resultCode, intent);
        finish();
    }

}