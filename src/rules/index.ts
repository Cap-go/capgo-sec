import type { Rule } from '../types.js';

import { secretsRules } from './secrets.js';
import { storageRules } from './storage.js';
import { networkRules } from './network.js';
import { capacitorRules } from './capacitor.js';
import { androidRules } from './android.js';
import { iosRules } from './ios.js';
import { authenticationRules } from './authentication.js';
import { webviewRules } from './webview.js';
import { loggingRules, debugRules } from './logging.js';
import { cryptographyRules } from './cryptography.js';

export const allRules: Rule[] = [
  ...secretsRules,
  ...storageRules,
  ...networkRules,
  ...capacitorRules,
  ...androidRules,
  ...iosRules,
  ...authenticationRules,
  ...webviewRules,
  ...loggingRules,
  ...debugRules,
  ...cryptographyRules
];

export const rulesByCategory = {
  secrets: secretsRules,
  storage: storageRules,
  network: networkRules,
  capacitor: capacitorRules,
  android: androidRules,
  ios: iosRules,
  authentication: authenticationRules,
  webview: webviewRules,
  logging: loggingRules,
  debug: debugRules,
  cryptography: cryptographyRules
};

export const ruleCount = allRules.length;

export {
  secretsRules,
  storageRules,
  networkRules,
  capacitorRules,
  androidRules,
  iosRules,
  authenticationRules,
  webviewRules,
  loggingRules,
  debugRules,
  cryptographyRules
};
