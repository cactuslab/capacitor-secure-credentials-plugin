package com.cactuslab.plugins.securecredentials;

import com.getcapacitor.JSObject;

public class SecureCredentialsError implements JsAble {

    private static final String ERROR_KEY = "error";
    private static final String CODE_KEY = "code";

    String errorMessage;
    String errorCode;

    SecureCredentialsError(String message, String code) {
        this.errorCode = code;
        this.errorMessage = message;
    }

    public JSObject toJS() {
        JSObject result = new JSObject();
        result.put(ERROR_KEY, errorMessage);
        result.put(CODE_KEY, errorCode);
        return result;
    }

    static final SecureCredentialsError failedToAccess = new SecureCredentialsError("We failed to access the keystore", "failedToAccess");
    static final SecureCredentialsError noData = new SecureCredentialsError("The credentials don't yet exist", "no data");
    static SecureCredentialsError unavailable(String message) {
        return new SecureCredentialsError(message, "unavailable");
    }
    static SecureCredentialsError unknown(String message) {
        return new SecureCredentialsError("Something went wrong \uD83D\uDE31: " + message, "unknown");
    }
    static SecureCredentialsError missingParameters = new SecureCredentialsError("Some parameters were missing", "missingParameters");
}
