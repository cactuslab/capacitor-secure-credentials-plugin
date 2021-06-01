# capacitor-secure-credentials-plugin

Saves credentials in a secure way

## Install

```bash
npm install capacitor-secure-credentials-plugin
npx cap sync
```

## API

<docgen-index>

* [`getCredential(...)`](#getcredential)
* [`getCredentials(...)`](#getcredentials)
* [`removeCredential(...)`](#removecredential)
* [`removeCredentials(...)`](#removecredentials)
* [`addCredential(...)`](#addcredential)
* [`setCredentials(...)`](#setcredentials)
* [`canUseSecurityLevel(...)`](#canusesecuritylevel)
* [`maximumAllowedSecurityLevel()`](#maximumallowedsecuritylevel)
* [Interfaces](#interfaces)
* [Enums](#enums)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getCredential(...)

```typescript
getCredential(options: { service: string; username: string; }) => any
```

Get a credential matching a service and username if one exists.

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>any</code>

--------------------


### getCredentials(...)

```typescript
getCredentials(options: { service: string; }) => any
```

Get all credentials stored in a service. 
A user may be challenged with an ID check every time this is called.

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>any</code>

--------------------


### removeCredential(...)

```typescript
removeCredential(options: { service: string; username: string; }) => any
```

Remove a specific credential

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>any</code>

--------------------


### removeCredentials(...)

```typescript
removeCredentials(options: { service: string; }) => any
```

Remove all credentials belonging to a service

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>any</code>

--------------------


### addCredential(...)

```typescript
addCredential(options: { credential: Credential; options?: CredentialOptions; }) => any
```

Add a credential into the secure store. This will overwrite any existing credential of the same service and username.

| Param         | Type                                                                                                                             |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ credential: <a href="#credential">Credential</a>; options?: <a href="#credentialoptions">CredentialOptions</a>; }</code> |

**Returns:** <code>any</code>

--------------------


### setCredentials(...)

```typescript
setCredentials(options: { service: string; credentials: CredentialSecret[]; options?: CredentialOptions; }) => any
```

Replace all credentials of a service with the credentials supplied.

| Param         | Type                                                                                                             |
| ------------- | ---------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ service: string; credentials: {}; options?: <a href="#credentialoptions">CredentialOptions</a>; }</code> |

**Returns:** <code>any</code>

--------------------


### canUseSecurityLevel(...)

```typescript
canUseSecurityLevel(options: { securityLevel: SecurityLevel; }) => any
```

Verify if the current platform can handle a particular security level.

| Param         | Type                                                                        |
| ------------- | --------------------------------------------------------------------------- |
| **`options`** | <code>{ securityLevel: <a href="#securitylevel">SecurityLevel</a>; }</code> |

**Returns:** <code>any</code>

--------------------


### maximumAllowedSecurityLevel()

```typescript
maximumAllowedSecurityLevel() => any
```

Determine the maximum allowed security level on a platform.
This may change over the course of an application's lifetime as users may add or remove pins or biometric scanning features.

**Returns:** <code>any</code>

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
| **`service`**  | <code>string</code> |


#### Failure

| Prop          | Type               |
| ------------- | ------------------ |
| **`success`** | <code>false</code> |
| **`error`**   | <code>E</code>     |


#### SecureCredentialsError

| Prop          | Type                                                    |
| ------------- | ------------------------------------------------------- |
| **`code`**    | <code>"failedToAccess" \| "no data" \| "unknown"</code> |
| **`message`** | <code>string</code>                                     |


#### CredentialOptions

| Prop                | Type                                                    |
| ------------------- | ------------------------------------------------------- |
| **`securityLevel`** | <code><a href="#securitylevel">SecurityLevel</a></code> |


#### CredentialSecret

| Prop           | Type                |
| -------------- | ------------------- |
| **`username`** | <code>string</code> |
| **`password`** | <code>string</code> |


### Enums


#### SecurityLevel

| Members                 | Value                            |
| ----------------------- | -------------------------------- |
| **`L1_Encrypted`**      | <code>'L1_Encrypted'</code>      |
| **`L2_DeviceUnlocked`** | <code>'L2_DeviceUnlocked'</code> |
| **`L3_UserPresence`**   | <code>'L3_UserPresence'</code>   |
| **`L4_Biometrics`**     | <code>'L4_Biometrics'</code>     |

</docgen-api>
