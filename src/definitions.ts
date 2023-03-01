export enum SecurityErrorCode {
    FailedToAccess = 'failed to access',
    NoData = 'no data',
    Unknown = 'unknown',
    Unavailable = 'unavailable',
    Params = 'params',
}

export enum SecurityLevel {
    L1_Encrypted = 1,
    L2_DeviceUnlocked = 2,
    L3_UserPresence = 3,
    L4_Biometrics = 4,
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

export interface BiometricSensors {
    face: boolean;
    fingerprint: boolean;
    iris: boolean;
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
     * Determine the maximum security level supported on the platform.
     * This may change over the course of an application's lifetime as users may add or remove pins or biometric scanning features.
     */
    maximumSecurityLevel(): Promise<Success<SecurityLevel> | Failure<SecureCredentialsError>>
    /**
     * Determine the device capabilities for biometric scanning features. A device may have any combination of sensors and the sensors
     * available may change depending on whether a user has granted permission to inspect the device sensors or whether they are enrolled
     * with those sensors. Not all devices advertise what sensors they have. The information gathered is not guaranteed to be 100% accurate. 
     */
    supportedBiometricSensors(): Promise<Success<BiometricSensors> | Failure<SecureCredentialsError>>
}
