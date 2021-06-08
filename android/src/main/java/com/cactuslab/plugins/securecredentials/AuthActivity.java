package com.cactuslab.plugins.securecredentials;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
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

    private Executor executor;
    private BiometricPrompt.PromptInfo promptInfo;
    private BiometricPrompt biometricPrompt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);

        // Search the intent for the service and username. Use that to get the crypto object to authenticate

        SecureCredentials.PasswordStorageHelper creds = new SecureCredentials.PasswordStorageHelper(this);
        String service = getIntent().getStringExtra(SERVICE_KEY);
        String username = getIntent().getStringExtra(USERNAME_KEY);


        // The successful result will be the decrypted String value
        executor = ContextCompat.getMainExecutor(this);

        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(getIntent().hasExtra("title") ? getIntent().getStringExtra("title") : "Authenticate")
                .setSubtitle(getIntent().hasExtra("subtitle") ? getIntent().getStringExtra("subtitle") : null)
                .setDescription(getIntent().hasExtra("description") ? getIntent().getStringExtra("description") : null)
                .setNegativeButtonText(getIntent().hasExtra("negativeButtonText") ? getIntent().getStringExtra("negativeButtonText") : "Cancel")
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
                    Cipher cipher = creds.getCipher(service, username);

                    byte[] decryptedInfo = SecureCredentials.PasswordStorageHelper.decrypt(cipher, creds.getEncryptedData(service, username));
                    finishActivity(RESULT_OK, new String(decryptedInfo));
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