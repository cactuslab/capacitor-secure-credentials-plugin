import { WebPlugin } from '@capacitor/core';

import type {
  Credential,
  GetCredentialsError,
  Failure,
  SecureCredentialsPlugin,
  SecurityLevels,
  Success
} from './definitions';

export class SecureCredentialsWeb extends WebPlugin implements SecureCredentialsPlugin {
  async getCredential(service: string, username: string): Promise<Success<Credential> | Failure<GetCredentialsError>> {
    return setTimeout(() => console.log('getCredential', service, username) , 1000) as unknown as Success<Credential> | Failure<GetCredentialsError>;
  }

  async getCredentials(service: string): Promise<string[]> {
    return setTimeout(() => console.log('getCredentials', service) , 1000) as unknown as string[];
  }

  async removeCredential(service: string, username: string): Promise<boolean> {
    return setTimeout(() => console.log('removeCredential', service, username) , 1000) as unknown as boolean;
  }

  async removeCredentials(service: string): Promise<boolean> {
    return setTimeout(() => console.log('removeCredentials', service) , 1000) as unknown as boolean;
  }

  async putCredential(options: { service: string }): Promise<{ value: boolean }> {
    return setTimeout(() => console.log('putCredential', options.service) , 1000) as unknown as { value: boolean };
  }

  async canUseProtection(securityLevel: SecurityLevels): Promise<boolean> {
    return setTimeout(() => console.log('canUseProtection', securityLevel) , 1000) as unknown as boolean;
  }
}
