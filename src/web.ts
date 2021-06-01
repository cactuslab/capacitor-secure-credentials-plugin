import { WebPlugin } from '@capacitor/core';

import type {
  Credential,
  Failure,
  SecureCredentialsError,
  SecureCredentialsPlugin,
  SecurityLevel,
  CredentialOptions,
  CredentialSecret,
  Success
} from './definitions';

export class SecureCredentialsWeb extends WebPlugin implements SecureCredentialsPlugin {
  async getCredential(options: { service: string, username: string }): Promise<Success<Credential> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> getCredential', options.service, options.username) , 1000) as unknown as Success<Credential> | Failure<SecureCredentialsError>;
  }

  async getCredentials(options: { service: string }): Promise<Success<Credential[]> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> getCredentials', options.service) , 1000) as unknown as Success<Credential[]> | Failure<SecureCredentialsError>;
  }

  async removeCredential(options: { service: string, username: string }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> removeCredential', options.service, options.username) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async removeCredentials(options: { service: string }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> removeCredentials', options.service) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async addCredential(options: { credential: Credential, options?: CredentialOptions }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> addCredential', options.credential.service) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async setCredentials(options: { service: string, credentials: CredentialSecret[], options?: CredentialOptions}): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> setCredentials', options.service) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async canUseSecurityLevel(options: { securityLevel: SecurityLevel }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> canUseProtection', options.securityLevel) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async maximumAllowedSecurityLevel(): Promise<Success<SecurityLevel> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> maximumAllowedSecurityLevel?') , 1000) as unknown as Success<SecurityLevel> | Failure<SecureCredentialsError>;
  }
}
