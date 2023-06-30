package com.cactuslab.plugins.securecredentials;

import org.json.JSONException;
import org.json.JSONObject;

public class MetaData {

    final SecurityStrategyName securityLevel;

    private static final String SECURITY_LEVEL_KEY = "strategy";

    MetaData(SecurityStrategyName level) {
        this.securityLevel = level;
    }

    MetaData(JSONObject jsonObject) throws JSONException {
        this.securityLevel = SecurityStrategyName.get(jsonObject.getString(SECURITY_LEVEL_KEY));
    }

    JSONObject asJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put(SECURITY_LEVEL_KEY, securityLevel.name);
        return object;
    }
}