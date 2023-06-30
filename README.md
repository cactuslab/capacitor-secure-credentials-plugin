# capacitor-secure-credentials-plugin

Saves credentials using secure native technology (Keychain on iOS and Android), with configurable protection levels from simply encrypted, device unlocked, user presence, to user presence proved with biometrics.

## Install

```bash
npm install capacitor-secure-credentials-plugin
npx cap sync
```

## API

<docgen-index>

* [`getCredential(...)`](#getcredential)
* [`getUsernames(...)`](#getusernames)
* [`removeCredential(...)`](#removecredential)
* [`removeCredentials(...)`](#removecredentials)
* [`setCredential(...)`](#setcredential)
* [`availableSecurityStrategies()`](#availablesecuritystrategies)
* [`supportedBiometricSensors()`](#supportedbiometricsensors)
* [Interfaces](#interfaces)
* [Type Aliases](#type-aliases)
* [Enums](#enums)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getCredential(...)

```typescript
getCredential(options: { service: string; username: string; }) => Promise<Success<Credential> | Failure<SecureCredentialsError>>
```

Get a credential matching a service and username if one exists.
The user may be challenged to authenticate this request every time it is called.

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>Promise&lt;<a href="#success">Success</a>&lt;<a href="#credential">Credential</a>&gt; | <a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt;&gt;</code>

--------------------


### getUsernames(...)

```typescript
getUsernames(options: { service: string; }) => Promise<Success<string[]> | Failure<SecureCredentialsError>>
```

Get all usernames that have credentials stored for a service.

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>Promise&lt;<a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt; | <a href="#success">Success</a>&lt;string[]&gt;&gt;</code>

--------------------


### removeCredential(...)

```typescript
removeCredential(options: { service: string; username: string; }) => Promise<Success<boolean> | Failure<SecureCredentialsError>>
```

Remove a specific credential

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>Promise&lt;<a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt; | <a href="#success">Success</a>&lt;boolean&gt;&gt;</code>

--------------------


### removeCredentials(...)

```typescript
removeCredentials(options: { service: string; }) => Promise<Success<boolean> | Failure<SecureCredentialsError>>
```

Remove all credentials belonging to a service

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>Promise&lt;<a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt; | <a href="#success">Success</a>&lt;boolean&gt;&gt;</code>

--------------------


### setCredential(...)

```typescript
setCredential(options: { service: string; credential: Credential; options: CredentialOptions; }) => Promise<Success<boolean> | Failure<SecureCredentialsError>>
```

Set a credential into the secure store. This will overwrite any existing credential of the same service and username.

| Param         | Type                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ service: string; credential: <a href="#credential">Credential</a>; options: <a href="#credentialoptions">CredentialOptions</a>; }</code> |

**Returns:** <code>Promise&lt;<a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt; | <a href="#success">Success</a>&lt;boolean&gt;&gt;</code>

--------------------


### availableSecurityStrategies()

```typescript
availableSecurityStrategies() => Promise<Success<SecurityStrategy[]> | Failure<SecureCredentialsError>>
```

Returns the available strategies for storing credentials, sorted strongest to weakest.

**Returns:** <code>Promise&lt;<a href="#failure">Failure</a>&lt;<a href="#securecredentialserror">SecureCredentialsError</a>&gt; | <a href="#success">Success</a>&lt;SecurityStrategy[]&gt;&gt;</code>

--------------------


### supportedBiometricSensors()

```typescript
supportedBiometricSensors() => Promise<Success<BiometricSensors>>
```

Determine the device capabilities for biometric scanning features. A device may have any combination of sensors and the sensors
available may change depending on whether a user has granted permission to inspect the device sensors or whether they are enrolled
with those sensors. Not all devices advertise what sensors they have. The information gathered is not guaranteed to be 100% accurate.

**Returns:** <code>Promise&lt;<a href="#success">Success</a>&lt;<a href="#biometricsensors">BiometricSensors</a>&gt;&gt;</code>

--------------------


### Interfaces


#### Success

| Prop          | Type              |
| ------------- | ----------------- |
| **`success`** | <code>true</code> |
| **`result`**  | <code>T</code>    |


#### Credential

| Prop           | Type                |
| -------------- | ------------------- |
| **`username`** | <code>string</code> |
| **`password`** | <code>string</code> |


#### Failure

| Prop          | Type               |
| ------------- | ------------------ |
| **`success`** | <code>false</code> |
| **`error`**   | <code>E</code>     |


#### SecureCredentialsError

| Prop          | Type                                                            |
| ------------- | --------------------------------------------------------------- |
| **`code`**    | <code><a href="#securityerrorcode">SecurityErrorCode</a></code> |
| **`message`** | <code>string</code>                                             |


#### CredentialOptions

| Prop           | Type                                                                  |
| -------------- | --------------------------------------------------------------------- |
| **`strategy`** | <code><a href="#securitystrategyname">SecurityStrategyName</a></code> |


#### SecurityStrategy

| Prop             | Type                                                                  |
| ---------------- | --------------------------------------------------------------------- |
| **`name`**       | <code><a href="#securitystrategyname">SecurityStrategyName</a></code> |
| **`level`**      | <code><a href="#securitylevel">SecurityLevel</a></code>               |
| **`biometrics`** | <code>boolean</code>                                                  |


#### BiometricSensors

| Prop              | Type                 |
| ----------------- | -------------------- |
| **`face`**        | <code>boolean</code> |
| **`fingerprint`** | <code>boolean</code> |
| **`iris`**        | <code>boolean</code> |


### Type Aliases


#### SecurityStrategyName

<code><a href="#opaque">Opaque</a>&lt;'<a href="#securitystrategyname">SecurityStrategyName</a>', string&gt;</code>


#### Opaque

<code>T & { __TYPE__: K }</code>


### Enums


#### SecurityErrorCode

| Members              | Value                           |
| -------------------- | ------------------------------- |
| **`FailedToAccess`** | <code>'failed to access'</code> |
| **`NoData`**         | <code>'no data'</code>          |
| **`Unknown`**        | <code>'unknown'</code>          |
| **`Unavailable`**    | <code>'unavailable'</code>      |
| **`Params`**         | <code>'params'</code>           |


#### SecurityLevel

| Members                 | Value          | Description                                                                                                                                                                                                                                                           |
| ----------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`L1_Encrypted`**      | <code>1</code> | The credential will be stored encrypted, but it can be accessed by the application while the device is locked.                                                                                                                                                        |
| **`L2_DeviceUnlocked`** | <code>2</code> | The credential will be stored encrypted, and it can only be accessed by the application when the device is unlocked.                                                                                                                                                  |
| **`L3_UserPresence`**   | <code>3</code> | The credential will be stored encrypted, and it can only be accessed by the application after the OS confirms the user is present by means of a challenge. The OS may remember that the user is present for a configured period of time after a device PIN challenge. |

</docgen-api>
