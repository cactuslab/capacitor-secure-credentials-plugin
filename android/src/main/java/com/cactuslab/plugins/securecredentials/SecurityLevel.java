package com.cactuslab.plugins.securecredentials;

public enum SecurityLevel {
    L1_ENCRYPTED ("L1_Encrypted"),
    L2_DEVICE_UNLOCKED ("L2_DeviceUnlocked"),
    L3_USER_PRESENCE ("L3_UserPresence"),
    L4_BIOMETRICS ("L4_Biometrics");

    final String level;

    SecurityLevel(String level) {
        this.level = level;
    }
}