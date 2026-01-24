// Capsec - Capacitor Security Scanner
// https://capacitor-sec.dev

export { SecurityScanner } from './scanners/engine.js';
export { formatCliReport, formatJsonReport, formatHtmlReport } from './utils/reporter.js';
export { allRules, rulesByCategory, ruleCount } from './rules/index.js';

export type {
  Rule,
  Finding,
  ScanResult,
  ScanOptions,
  Severity,
  RuleCategory,
  CapacitorConfig
} from './types.js';

// Re-export individual rule sets for custom configurations
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
} from './rules/index.js';
