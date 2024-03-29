# capacitor-secure-credentials-plugin

## 3.0.1

### Patch Changes

- 25295e3: android: fixes key validity issue with Huawei P20 and P30 devices

## 3.0.0

### Major Changes

- d20b218: Manage credentials using Strategies in place of Security Levels

## 2.0.1

### Patch Changes

- a02aaf6: package: update capacitor
- 3a9a751: android: Fix android 28 & 29 support for biometric reporting

## 2.0.0

### Major Changes

- 4cf66e7: capacitor: Updated to support Capacitor 5

## 1.1.1

### Patch Changes

- 2bfecee: Android: Present biometrics over current context

## 1.1.0

### Minor Changes

- d0deca6: Added supportedBiometricSensors function to help determine what kind of biometric sensor a device might have

## 1.0.1

### Patch Changes

- 6312ea1: Android: Added logging on plugin interface to make it easier to debug
- b977444: Android: Fixed credential return result to match Credential type

## 1.0.0

### Major Changes

- 76de6b1: Remove defunct canUseSecurityLevel API
- d83f1ca: Rename maximumAllowedSecurityLevel to maximumSecurityLevel

### Minor Changes

- f0032a8: Tidy error codes
- ec48503: Change security levels to an int-backed enum so you can compare levels easily
- 67629fc: Fix misreporting of maximum security level as L2 when it should be L3

## 0.2.1

### Patch Changes

- 3a70bbf: Android: Updated dependencies to remove jcenter reference

## 0.2.0

### Minor Changes

- a72f162: Add params error type

## 0.1.0

### Minor Changes

- dddb875: iOS: fix error structure to match TypeScript definition

### Patch Changes

- 7c56d23: Upgrade dependencies
- f2ad478: iOS: upgrade minimum iOS version to 13 for @capacitor/ios changes
- ec071e0: Android update for @capacitor/android upgrade
