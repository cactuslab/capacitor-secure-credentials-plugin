type L1_Encrypted = 'L1_Encrypted';
type L2_DeviceUnlocked = 'L2_DeviceUnlocked';
type L3_UserPresence = 'L3_UserPresence';
type L4_Biometrics = 'L4_Biometrics';
type errorCode = 'failedToAccess' | 'no data' | 'unknown';

export type SecurityLevels = L1_Encrypted | L2_DeviceUnlocked | L3_UserPresence | L4_Biometrics;

export interface Credential {
    username: string;
    password: string;
    service: string;
}

export interface Success<T> {
    success: true;
    result: T;
}

export interface Failure<E> {
    success: false;
    error: E
}

export interface SecureCredentialsError {
    code: errorCode;
    message: string;
}

export interface SecureCredentialsPlugin {
    getCredential(options: { service: string, username: string }): Promise<Success<Credential> | Failure<SecureCredentialsError>>;
    getCredentials(options: { service: string }): Promise<Success<string[]> | Failure<SecureCredentialsError>>;
    removeCredential(options: { service: string, username: string }): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    removeCredentials(options: { service: string }): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    putCredential(options: { service: string, username: string, password: string, options?: { securityLevel?: SecurityLevels, minimumSecurityLevel?: SecurityLevels } }): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
    canUseSecurityLevel(options: { securityLevel: SecurityLevels }): Promise<Success<boolean> | Failure<SecureCredentialsError>>;
}
