import { WebPlugin } from '@capacitor/core';

import {
  Credential,
  Failure,
  SecureCredentialsError,
  SecureCredentialsPlugin,
  Success,
  CredentialOptions,
  BiometricSensors,
  SecurityStrategy
} from './definitions';

export class SecureCredentialsWeb extends WebPlugin implements SecureCredentialsPlugin {

  async getCredential(options: {service: string, username: string}): Promise<Success<Credential> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> getCredential', options) , 1000) as unknown as Success<Credential> | Failure<SecureCredentialsError>;
  }

  async getUsernames(options: {service: string}): Promise<Success<string[]> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> getUsernames', options) , 1000) as unknown as Success<string[]> | Failure<SecureCredentialsError>;
  }

  async removeCredential(options: {service: string, username: string}): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> removeCredential', options) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async removeCredentials(options: {service: string}): Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> removeCredentials', options) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async setCredential(options: {service: string, credential: Credential, options?: CredentialOptions}) : Promise<Success<boolean> | Failure<SecureCredentialsError>> {
    return setTimeout(() => console.log('WEB -> setCredential', options) , 1000) as unknown as Success<boolean> | Failure<SecureCredentialsError>;
  }

  async availableSecurityStrategies(): Promise<Success<SecurityStrategy[]> | Failure<SecureCredentialsError>> {
      return setTimeout(() => console.log('WEB -> availableSecurityStrategies') , 1000) as unknown as Success<SecurityStrategy[]> | Failure<SecureCredentialsError>;
  }

  async supportedBiometricSensors(): Promise<Success<BiometricSensors>> {
      return setTimeout(() => console.log('WEB -> supportedBiometricSensors?') , 1000) as unknown as Success<BiometricSensors>;
  }
}
