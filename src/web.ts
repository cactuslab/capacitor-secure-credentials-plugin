import { WebPlugin } from '@capacitor/core';

import type {
  Credential,
  Failure,
  SecureCredentialsError,
  SecureCredentialsPlugin,
  SecurityLevels,
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

  async putCredential(options: { service: string, username: string, password: string, options?: { securityLevel?: SecurityLevels, minimumSecurityLevel?: SecurityLevels } }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> putCredential', options.service) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async canUseSecurityLevel(options: { securityLevel: SecurityLevels }): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> canUseProtection', options.securityLevel) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }
}
