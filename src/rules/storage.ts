import type { Rule, Finding } from '../types.js';

export const storageRules: Rule[] = [
  {
    id: 'STO001',
    name: 'Unencrypted Sensitive Data in Preferences',
    description: 'Detects storage of sensitive data in Capacitor Preferences without encryption',
    severity: 'high',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Pattern for Preferences.set with sensitive keys
      const sensitiveKeys = /(?:password|token|secret|key|auth|session|credential|pin|ssn|credit.?card)/i;
      const preferencesPattern = /Preferences\.set\s*\(\s*\{[^}]*key:\s*['"]([^'"]+)['"]/g;

      let match;
      while ((match = preferencesPattern.exec(content)) !== null) {
        const keyName = match[1];
        if (sensitiveKeys.test(keyName)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'STO001',
            ruleName: 'Unencrypted Sensitive Data in Preferences',
            severity: 'high',
            category: 'storage',
            message: `Sensitive data "${keyName}" stored in Preferences without encryption`,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use @capgo/capacitor-native-biometric or iOS Keychain/Android Keystore for sensitive data storage.',
            references: [
              'https://capacitor-sec.dev/docs/rules/storage',
              'https://capacitorjs.com/docs/apis/preferences'
            ]
          });
        }
      }

      return findings;
    },
    remediation: 'Use secure storage solutions like @capgo/capacitor-native-biometric for sensitive data.'
  },
  {
    id: 'STO002',
    name: 'localStorage Usage for Sensitive Data',
    description: 'Detects usage of localStorage for storing sensitive information',
    severity: 'high',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const sensitiveKeys = /(?:password|token|secret|key|auth|session|credential|pin|ssn|credit.?card|jwt|bearer)/i;
      const localStoragePattern = /localStorage\.setItem\s*\(\s*['"]([^'"]+)['"]/g;

      let match;
      while ((match = localStoragePattern.exec(content)) !== null) {
        const keyName = match[1];
        if (sensitiveKeys.test(keyName)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'STO002',
            ruleName: 'localStorage Usage for Sensitive Data',
            severity: 'high',
            category: 'storage',
            message: `Sensitive data "${keyName}" stored in localStorage which is not secure`,
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Use Capacitor Preferences with encryption or secure native storage instead of localStorage.',
            references: ['https://capacitor-sec.dev/docs/rules/localstorage']
          });
        }
      }

      return findings;
    },
    remediation: 'Avoid localStorage for sensitive data. Use Capacitor\'s secure storage APIs.'
  },
  {
    id: 'STO003',
    name: 'SQLite Database Without Encryption',
    description: 'Detects SQLite database usage without encryption enabled',
    severity: 'medium',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for SQLite plugin without encryption
      const sqlitePattern = /(?:CapacitorSQLite|SQLite)\.(?:createConnection|open)\s*\(/g;
      const hasEncryption = /encrypted:\s*true|secret:\s*['"][^'"]+['"]/;

      let match;
      while ((match = sqlitePattern.exec(content)) !== null) {
        // Look for encryption in the surrounding context (100 chars)
        const context = content.substring(Math.max(0, match.index - 50), match.index + 200);
        if (!hasEncryption.test(context)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'STO003',
            ruleName: 'SQLite Database Without Encryption',
            severity: 'medium',
            category: 'storage',
            message: 'SQLite database created without encryption enabled',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Enable SQLite encryption using the encrypted option and provide a secure encryption key.',
            references: ['https://github.com/capacitor-community/sqlite']
          });
        }
      }

      return findings;
    },
    remediation: 'Enable SQLCipher encryption for SQLite databases containing sensitive data.'
  },
  {
    id: 'STO004',
    name: 'Filesystem Storage of Sensitive Data',
    description: 'Detects writing sensitive data to the filesystem without encryption',
    severity: 'high',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const writePattern = /Filesystem\.writeFile\s*\(/g;
      const sensitiveContent = /(?:password|token|secret|key|auth|credential|private)/i;

      let match;
      while ((match = writePattern.exec(content)) !== null) {
        const context = content.substring(match.index, Math.min(content.length, match.index + 300));
        if (sensitiveContent.test(context)) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'STO004',
            ruleName: 'Filesystem Storage of Sensitive Data',
            severity: 'high',
            category: 'storage',
            message: 'Potentially sensitive data written to filesystem without encryption',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Encrypt sensitive data before writing to filesystem. Consider using secure storage alternatives.',
            references: ['https://capacitorjs.com/docs/apis/filesystem']
          });
        }
      }

      return findings;
    },
    remediation: 'Encrypt data before filesystem storage or use secure storage APIs.'
  },
  {
    id: 'STO005',
    name: 'Insecure Data Caching',
    description: 'Detects caching of sensitive data that could persist beyond session',
    severity: 'medium',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for various caching patterns with sensitive data
      const cachePatterns = [
        /sessionStorage\.setItem\s*\(\s*['"](?:[^'"]*(?:token|auth|session|credential)[^'"]*)['"]/gi,
        /\.cache\s*\(\s*['"](?:[^'"]*(?:token|auth|user|session)[^'"]*)['"]/gi,
        /IndexedDB.*(?:token|auth|password|credential)/gi
      ];

      for (const pattern of cachePatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'STO005',
            ruleName: 'Insecure Data Caching',
            severity: 'medium',
            category: 'storage',
            message: 'Sensitive data may be cached insecurely',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim(),
            remediation: 'Avoid caching sensitive data. If necessary, use encrypted storage with proper expiration.',
            references: ['https://capacitor-sec.dev/docs/rules/caching']
          });
        }
      }

      return findings;
    },
    remediation: 'Implement secure caching with encryption and proper data expiration.'
  },
  {
    id: 'STO006',
    name: 'Keychain/Keystore Not Used for Credentials',
    description: 'Detects credential storage that should use native secure storage',
    severity: 'high',
    category: 'storage',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Check for credential storage without using native biometric/secure storage
      const insecureStoragePattern = /(?:Preferences|localStorage|sessionStorage).*(?:password|credential|biometric|pin)/gi;

      let match;
      while ((match = insecureStoragePattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'STO006',
          ruleName: 'Keychain/Keystore Not Used for Credentials',
          severity: 'high',
          category: 'storage',
          message: 'Credentials should be stored in iOS Keychain or Android Keystore',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Use @capgo/capacitor-native-biometric or similar plugin for secure credential storage.',
          references: [
            'https://github.com/nickcox/capacitor-native-biometric',
            'https://capacitor-sec.dev/docs/rules/secure-storage'
          ]
        });
      }

      return findings;
    },
    remediation: 'Use iOS Keychain and Android Keystore through appropriate Capacitor plugins.'
  }
];
