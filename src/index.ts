import { registerPlugin } from '@capacitor/core';

import type { SecureCredentialsPlugin } from './definitions';

const SecureCredentials = registerPlugin<SecureCredentialsPlugin>(
  'SecureCredentials',
  {
    web: () => import('./web').then(m => new m.SecureCredentialsWeb()),
  },
);

export * from './definitions';
export { SecureCredentials };
