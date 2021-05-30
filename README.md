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
* [`canUseProtection(...)`](#canuseprotection)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getCredential(...)

```typescript
getCredential(service: string, username: string) => any
```

| Param          | Type                |
| -------------- | ------------------- |
| **`service`**  | <code>string</code> |
| **`username`** | <code>string</code> |

**Returns:** <code>any</code>

--------------------


### getCredentials(...)

```typescript
getCredentials(service: string) => any
```

| Param         | Type                |
| ------------- | ------------------- |
| **`service`** | <code>string</code> |

**Returns:** <code>any</code>

--------------------


### removeCredential(...)

```typescript
removeCredential(service: string, username: string) => any
```

| Param          | Type                |
| -------------- | ------------------- |
| **`service`**  | <code>string</code> |
| **`username`** | <code>string</code> |

**Returns:** <code>any</code>

--------------------


### removeCredentials(...)

```typescript
removeCredentials(service: string) => any
```

| Param         | Type                |
| ------------- | ------------------- |
| **`service`** | <code>string</code> |

**Returns:** <code>any</code>

--------------------


### putCredential(...)

```typescript
putCredential(options: { service: string; }) => any
```

| Param         | Type                              |
| ------------- | --------------------------------- |
| **`options`** | <code>{ service: string; }</code> |

**Returns:** <code>any</code>

--------------------


### canUseProtection(...)

```typescript
canUseProtection(securityLevel: SecurityLevels) => any
```

| Param               | Type                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------ |
| **`securityLevel`** | <code>"L1_Encrypted" \| "L2_DeviceUnlocked" \| "L3_UserPresence" \| "L4_Biometrics"</code> |

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


#### Failure

| Prop          | Type               |
| ------------- | ------------------ |
| **`success`** | <code>false</code> |
| **`error`**   | <code>E</code>     |


#### GetCredentialsError

| Prop          | Type                                                    |
| ------------- | ------------------------------------------------------- |
| **`code`**    | <code>"failedToAccess" \| "no data" \| "unknown"</code> |
| **`message`** | <code>string</code>                                     |

</docgen-api>
