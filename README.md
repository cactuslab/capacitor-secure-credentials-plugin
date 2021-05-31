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
* [`putCredential(...)`](#putcredential)
* [`canUseSecurityLevel(...)`](#canusesecuritylevel)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getCredential(...)

```typescript
getCredential(options: { service: string; username: string; }) => any
```

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>any</code>

--------------------


### getCredentials(...)

```typescript
getCredentials(options: { service: string; }) => any
```

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>any</code>

--------------------


### removeCredential(...)

```typescript
removeCredential(options: { service: string; username: string; }) => any
```

| Param         | Type                                                |
| ------------- | --------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; }</code> |

**Returns:** <code>any</code>

--------------------


### removeCredentials(...)

```typescript
removeCredentials(options: { service: string; }) => any
```

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>any</code>

--------------------


### putCredential(...)

```typescript
putCredential(options: { service: string; username: string; password: string; options?: { securityLevel?: SecurityLevels; minimumSecurityLevel?: SecurityLevels; }; }) => any
```

| Param         | Type                                                                                                                                                                                                                                                                                      |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ service: string; username: string; password: string; options?: { securityLevel?: "L1_Encrypted" \| "L2_DeviceUnlocked" \| "L3_UserPresence" \| "L4_Biometrics"; minimumSecurityLevel?: "L1_Encrypted" \| "L2_DeviceUnlocked" \| "L3_UserPresence" \| "L4_Biometrics"; }; }</code> |

**Returns:** <code>any</code>

--------------------


### canUseSecurityLevel(...)

```typescript
canUseSecurityLevel(options: { securityLevel: SecurityLevels; }) => any
```

| Param         | Type                                            |
| ------------- | ----------------------------------------------- |
| **`options`** | <code>{ securityLevel: SecurityLevels; }</code> |

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

</docgen-api>
