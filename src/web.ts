import { WebPlugin } from '@capacitor/core';

import type { SecureCredentialsPlugin } from './definitions';

export class SecureCredentialsWeb
  extends WebPlugin
  implements SecureCredentialsPlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
}
