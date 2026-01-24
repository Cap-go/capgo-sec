import type { Rule, Finding } from '../types.js';

export const loggingRules: Rule[] = [
  {
    id: 'LOG001',
    name: 'Sensitive Data in Console Logs',
    description: 'Detects logging of sensitive data to console',
    severity: 'high',
    category: 'logging',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test files
      if (filePath.includes('.test.') || filePath.includes('.spec.')) {
        return findings;
      }

      // Check for console logs with sensitive data
      const consolePattern = /console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|token|secret|key|auth|credential|apikey|bearer|jwt)[^)]*\)/gi;

      let match;
      while ((match = consolePattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'LOG001',
          ruleName: 'Sensitive Data in Console Logs',
          severity: 'high',
          category: 'logging',
          message: 'Sensitive data may be exposed in console output',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Remove sensitive data from logs. Use structured logging with data masking.',
          references: ['https://capacitor-sec.dev/docs/rules/logging']
        });
      }

      return findings;
    },
    remediation: 'Remove sensitive data from logs or implement data masking.'
  },
  {
    id: 'LOG002',
    name: 'Console Logs in Production',
    description: 'Detects console.log statements that should be removed in production',
    severity: 'low',
    category: 'logging',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];

      // Skip test files, dev files, and build scripts
      if (filePath.includes('.test.') || filePath.includes('.spec.') ||
          filePath.includes('.dev.') || filePath.includes('scripts/')) {
        return findings;
      }

      // Count console.log statements
      const consoleLogCount = (content.match(/console\.log\s*\(/g) || []).length;

      if (consoleLogCount > 5) {
        findings.push({
          ruleId: 'LOG002',
          ruleName: 'Console Logs in Production',
          severity: 'low',
          category: 'logging',
          message: `File contains ${consoleLogCount} console.log statements that may be visible in production`,
          filePath,
          line: 1,
          remediation: 'Remove or conditionally disable console.log in production builds.',
          references: ['https://capacitor-sec.dev/docs/rules/console-logs']
        });
      }

      return findings;
    },
    remediation: 'Use a proper logging library that can be disabled in production.'
  }
];

export const debugRules: Rule[] = [
  {
    id: 'DBG001',
    name: 'Debugger Statement',
    description: 'Detects debugger statements left in code',
    severity: 'medium',
    category: 'debug',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      const debuggerPattern = /\bdebugger\b/g;

      let match;
      while ((match = debuggerPattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'DBG001',
          ruleName: 'Debugger Statement',
          severity: 'medium',
          category: 'debug',
          message: 'Debugger statement found - will pause execution in development tools',
          filePath,
          line: lineNum,
          codeSnippet: lines[lineNum - 1]?.trim(),
          remediation: 'Remove debugger statements before production deployment.',
          references: ['https://capacitor-sec.dev/docs/rules/debugger']
        });
      }

      return findings;
    },
    remediation: 'Remove all debugger statements.'
  },
  {
    id: 'DBG002',
    name: 'Test Credentials in Code',
    description: 'Detects test or demo credentials in source code',
    severity: 'high',
    category: 'debug',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/*.json'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip actual test files
      if (filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__tests__')) {
        return findings;
      }

      const testCredPatterns = [
        /test(?:user|account|email|password)\s*[:=]\s*['"][^'"]+['"]/gi,
        /demo(?:user|account|password)\s*[:=]\s*['"][^'"]+['"]/gi,
        /admin(?:password|pass)\s*[:=]\s*['"][^'"]+['"]/gi,
        /(?:password|email)\s*[:=]\s*['"](?:test|demo|admin|password|123456|qwerty)['"]/gi
      ];

      for (const pattern of testCredPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'DBG002',
            ruleName: 'Test Credentials in Code',
            severity: 'high',
            category: 'debug',
            message: 'Test/demo credentials found in source code',
            filePath,
            line: lineNum,
            codeSnippet: lines[lineNum - 1]?.trim().replace(/['"][^'"]{5,}['"]/g, '"***"'),
            remediation: 'Remove test credentials from source code. Use environment-based configuration.',
            references: ['https://capacitor-sec.dev/docs/rules/test-credentials']
          });
        }
      }

      return findings;
    },
    remediation: 'Remove test credentials and use environment variables.'
  },
  {
    id: 'DBG003',
    name: 'Development URL in Production',
    description: 'Detects localhost or development URLs that may be left in code',
    severity: 'medium',
    category: 'debug',
    filePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/capacitor.config.*'],
    check: (content: string, filePath: string): Finding[] => {
      const findings: Finding[] = [];
      const lines = content.split('\n');

      // Skip test and config files typically used for dev
      if (filePath.includes('.test.') || filePath.includes('.spec.') ||
          filePath.includes('.local.') || filePath.includes('.dev.')) {
        return findings;
      }

      // Check for dev URLs in non-conditional code
      const devUrlPatterns = [
        /['"]http:\/\/localhost[^'"]*['"]/g,
        /['"]http:\/\/127\.0\.0\.1[^'"]*['"]/g,
        /['"]http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}[^'"]*['"]/g,
        /['"]http:\/\/192\.168\.[^'"]+['"]/g
      ];

      for (const pattern of devUrlPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          // Check if it's in a development condition
          const context = content.substring(Math.max(0, match.index - 100), match.index);
          const isDevelopmentGuard = /(?:isDev|process\.env\.NODE_ENV|__DEV__|development)/i.test(context);

          if (!isDevelopmentGuard) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            findings.push({
              ruleId: 'DBG003',
              ruleName: 'Development URL in Production',
              severity: 'medium',
              category: 'debug',
              message: 'Development URL found that may be accessible in production',
              filePath,
              line: lineNum,
              codeSnippet: lines[lineNum - 1]?.trim(),
              remediation: 'Use environment variables for URLs. Guard development URLs with environment checks.',
              references: ['https://capacitor-sec.dev/docs/rules/dev-urls']
            });
          }
        }
      }

      return findings;
    },
    remediation: 'Use environment-based URL configuration.'
  }
];
