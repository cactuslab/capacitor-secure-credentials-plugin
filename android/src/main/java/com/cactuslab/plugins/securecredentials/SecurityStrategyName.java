package com.cactuslab.plugins.securecredentials;

import androidx.annotation.Nullable;

public enum SecurityStrategyName {
    STRONG_USER_PRESENCE("StrongUserPresence"),
    PIN_USER_PRESENCE("PinUserPresence"),
    STANDARD_PLUS_BIO_CHECK("StandardPlusBioCheck"),
    STANDARD("Standard");

    final String name;

    SecurityStrategyName(String name) {
        this.name = name;
    }

    @Nullable
    public static SecurityStrategyName get(String name) {
        for (SecurityStrategyName aLevel : values()) {
            if (aLevel.name.equals(name)) {
                return aLevel;
            }
        }
        throw new IllegalArgumentException("Invalid security strategy: " + name);
    }
}

