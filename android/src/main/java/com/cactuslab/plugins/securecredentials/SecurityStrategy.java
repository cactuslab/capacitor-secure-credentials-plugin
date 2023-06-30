package com.cactuslab.plugins.securecredentials;

import com.getcapacitor.JSObject;

public class SecurityStrategy implements JsAble {

    private static final String SECURITY_LEVEL_KEY = "level";
    private static final String SECURITY_NAME_KEY = "name";
    private static final String SECURITY_BIOMETRICS_KEY = "biometrics";

    public final SecurityStrategyName name;
    public final SecurityLevel securityLevel;
    public final boolean biometrics;

    SecurityStrategy(SecurityStrategyName name, SecurityLevel securityLevel, boolean biometrics) {
        this.name = name;
        this.securityLevel = securityLevel;
        this.biometrics = biometrics;
    }

    @Override
    public JSObject toJS() {
        JSObject object = new JSObject();
        object.put(SECURITY_LEVEL_KEY, securityLevel.value);
        object.put(SECURITY_NAME_KEY, name.name);
        object.put(SECURITY_BIOMETRICS_KEY, biometrics);
        return object;
    }
}
