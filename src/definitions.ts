export enum SecurityErrorCode {
    FailedToAccess = 'failed to access',
    NoData = 'no data',
    Unknown = 'unknown',
    Unavailable = 'unavailable',
    Params = 'params',
}

export enum SecurityLevel {
    L1_Encrypted = 'L1_Encrypted',
    L2_DeviceUnlocked = 'L2_DeviceUnlocked',
    L3_UserPresence = 'L3_UserPresence',
    L4_Biometrics = 'L4_Biometrics'
}
export interface Credential {
    username: string;
    password: string;
}

export interface Success<T> {
    success: true;
    result: T;
}

export interface Failure<E> {
    success: false;
    error: E
}

export interface CredentialOptions {
    securityLevel?: SecurityLevel
}
export interface SecureCredentialsError {
    code: SecurityErrorCode;
    message: string;
}

export interface SecureCredentialsPlugin {
    /**
     * Get a credential matching a service and username if one exists.
     * The user may be challenged to authenticate this request every time it is called.
     */
    getCredential(options: {service: string, username: string}): Promise<Success<Credential> | Failure<SecureCredentialsError>>;
    /** 
     * Get all usernames that have credentials stored for a service.
     */
    getUsernames(options: {service: string}): Promise<Success<string[]> | Failure<SecureCredentialsError>>;
    /** 
     * Remove a specific credential 
     */
    removeCredential(options: {service: string, username: string}): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    /** 
     * Remove all credentials belonging to a service 
     */
    removeCredentials(options: {service: string}): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    /** 
     * Set a credential into the secure store. This will overwrite any existing credential of the same service and username. 
     */
    setCredential(options: {service: string, credential: Credential, options?: CredentialOptions}): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    /**
     * Verify if the current platform can handle a particular security level.
     */
    canUseSecurityLevel(options: {securityLevel: SecurityLevel}): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    /**
     * Determine the maximum allowed security level on a platform.
     * This may change over the course of an application's lifetime as users may add or remove pins or biometric scanning features.
     */
    maximumAllowedSecurityLevel(): Promise<Success<SecurityLevel> | Failure<SecureCredentialsError>>
}
