export enum SecurityErrorCode {
    FailedToAccess = 'failed to access',
    NoData = 'no data',
    Unknown = 'unknown',
    Unavailable = 'unavailable',
    Params = 'params',
}

export enum SecurityLevel {
    /**
     * The credential will be stored encrypted, but it can be accessed by the application while the device is locked.
     */
    L1_Encrypted = 1,
    /**
     * The credential will be stored encrypted, and it can only be accessed by the application when the
     * device is unlocked.
     */
    L2_DeviceUnlocked = 2,
    /**
     * The credential will be stored encrypted, and it can only be accessed by the application after the OS
     * confirms the user is present by means of a challenge. The OS may remember that the user is
     * present for a configured period of time after a device PIN challenge.
     */
    L3_UserPresence = 3,
}

type Opaque<K, T> = T & { __TYPE__: K }

export type SecurityStrategyName = Opaque<'SecurityStrategyName', string>

export interface SecurityStrategy {
    name: SecurityStrategyName
    level: SecurityLevel
    biometrics: boolean
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
    strategy: SecurityStrategyName
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
    setCredential(options: {service: string, credential: Credential, options: CredentialOptions}): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    /**
     * Returns the available strategies for storing credentials, sorted strongest to weakest.
     */
    availableSecurityStrategies(): Promise<Success<SecurityStrategy[]> | Failure<SecureCredentialsError>>
    /**
     * Determine the device capabilities for biometric scanning features. A device may have any combination of sensors and the sensors
     * available may change depending on whether a user has granted permission to inspect the device sensors or whether they are enrolled
     * with those sensors. Not all devices advertise what sensors they have. The information gathered is not guaranteed to be 100% accurate. 
     */
    supportedBiometricSensors(): Promise<Success<BiometricSensors>>
}
