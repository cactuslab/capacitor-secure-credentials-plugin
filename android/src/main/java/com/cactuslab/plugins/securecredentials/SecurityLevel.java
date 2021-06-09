package com.cactuslab.plugins.securecredentials;

import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;

public enum SecurityLevel {
    L1_ENCRYPTED ("L1_Encrypted", 1),
    L2_DEVICE_UNLOCKED ("L2_DeviceUnlocked", 2),
    L3_USER_PRESENCE ("L3_UserPresence", 3),
    L4_BIOMETRICS ("L4_Biometrics", 4);

    final String level;
    final int comparisonValue;

    SecurityLevel(String level, int comparisonValue) {
        this.level = level;
        this.comparisonValue = comparisonValue;
    }

    private static final Map<String, SecurityLevel> lookup = new HashMap<>();

    static {
        for (SecurityLevel level : SecurityLevel.values()) {
            lookup.put(level.level, level);
        }
    }

    @Nullable
    public static SecurityLevel get(@Nullable String level) {
        if (level == null) {
            return null;
        }
        return lookup.get(level);
    }
}