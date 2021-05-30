type L1_Encrypted = 'L1_Encrypted';
type L2_DeviceUnlocked = 'L2_DeviceUnlocked';
type L3_UserPresence = 'L3_UserPresence';
type L4_Biometrics = 'L4_Biometrics';

export type SecurityLevels = L1_Encrypted | L2_DeviceUnlocked | L3_UserPresence | L4_Biometrics;

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

export interface GetCredentialsError {
    code: 'failedToAccess' | 'no data' | 'unknown';
    message: string;
}

export interface SecureCredentialsPlugin {
    getCredential(service: string, username: string): Promise<Success<Credential> | Failure<GetCredentialsError>>;
    getCredentials(service: string): Promise<string[]>;
    removeCredential(service: string, username: string): Promise<boolean>;
    removeCredentials(service: string): Promise<boolean>;
    putCredential(options: { service: string }): Promise<{ value: boolean }>;
    canUseProtection(securityLevel: SecurityLevels): Promise<boolean>;
}
