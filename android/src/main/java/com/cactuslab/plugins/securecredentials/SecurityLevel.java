package com.cactuslab.plugins.securecredentials;

import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;

public enum SecurityLevel {
    L1_ENCRYPTED (1),
    L2_DEVICE_UNLOCKED (2),
    L3_USER_PRESENCE (3),
    L4_BIOMETRICS (4);

    final int value;

    SecurityLevel(int value) {
        this.value = value;
    }

    @Nullable
    public static SecurityLevel get(int level) {
        for (SecurityLevel aLevel : values()) {
            if (aLevel.value == level) {
                return aLevel;
            }
        }
        throw new IllegalArgumentException("Invalid security level: " + level);
    }
}