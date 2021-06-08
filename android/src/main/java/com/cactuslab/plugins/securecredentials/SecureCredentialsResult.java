package com.cactuslab.plugins.securecredentials;

import androidx.annotation.Nullable;

import com.getcapacitor.JSObject;

public class SecureCredentialsResult<T> implements JsAble {

    private static final String SUCCESS_KEY = "success";
    private static final String ERROR_KEY = "error";
    private static final String RESULT_KEY = "result";

    @Nullable
    private final T result;

    private final boolean success;

    SecureCredentialsResult(boolean success, @Nullable T result) {
        this.success = success;
        this.result = result;
    }

    @Override
    public JSObject toJS() {
        JSObject container = new JSObject();
        container.put(SUCCESS_KEY, success);
        if (success) {
            if (result != null) {
                if (result instanceof JsAble) {
                    container.put(RESULT_KEY, ((JsAble) result).toJS());
                } else {
                    container.put(RESULT_KEY, result);
                }
            }
        } else {
            if (result != null && result instanceof JsAble) {
                container.put(ERROR_KEY, ((JsAble) result).toJS());
            } else {
                container.put(ERROR_KEY, result);
            }
        }

        return container;
    }

    public static SecureCredentialsResult<Object> successResult = new SecureCredentialsResult<>(true, null);
    public static SecureCredentialsResult<SecureCredentialsError> errorResult(@Nullable SecureCredentialsError error) {
        return new SecureCredentialsResult<>(false, error);
    }
}
