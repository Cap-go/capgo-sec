import fg from 'fast-glob';
import { allRules, ruleCount } from '../rules/index.js';
import type { Rule, Finding, ScanResult, ScanOptions, RuleCategory, Severity } from '../types.js';

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
  '**/vendor/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/android/app/build/**',
  '**/ios/Pods/**',
  '**/ios/build/**'
];

export class SecurityScanner {
  private rules: Rule[];
  private options: ScanOptions;

  constructor(options: ScanOptions) {
    this.options = options;
    this.rules = this.filterRules(allRules);
  }

  private filterRules(rules: Rule[]): Rule[] {
    let filtered = rules;

    // Filter by severity
    if (this.options.severity) {
      const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      const minIndex = severityOrder.indexOf(this.options.severity);
      filtered = filtered.filter(rule => {
        const ruleIndex = severityOrder.indexOf(rule.severity);
        return ruleIndex <= minIndex;
      });
    }

    // Filter by category
    if (this.options.categories && this.options.categories.length > 0) {
      filtered = filtered.filter(rule => this.options.categories!.includes(rule.category));
    }

    return filtered;
  }

  async scan(): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    // Get all files to scan
    const files = await this.getFiles();

    // Process each file
    for (const file of files) {
      const fileFindings = await this.scanFile(file);
      findings.push(...fileFindings);
    }

    const duration = Date.now() - startTime;

    return {
      projectPath: this.options.path,
      timestamp: new Date().toISOString(),
      duration,
      filesScanned: files.length,
      findings: this.sortFindings(findings),
      summary: this.generateSummary(findings)
    };
  }

  private async getFiles(): Promise<string[]> {
    const excludePatterns = [...DEFAULT_EXCLUDE, ...(this.options.exclude || [])];

    // Collect all unique file patterns from rules
    const patterns = new Set<string>();
    for (const rule of this.rules) {
      if (rule.filePatterns) {
        rule.filePatterns.forEach(p => patterns.add(p));
      }
    }

    // If no patterns, use common source files
    if (patterns.size === 0) {
      patterns.add('**/*.ts');
      patterns.add('**/*.tsx');
      patterns.add('**/*.js');
      patterns.add('**/*.jsx');
      patterns.add('**/*.json');
      patterns.add('**/*.html');
      patterns.add('**/AndroidManifest.xml');
      patterns.add('**/Info.plist');
    }

    const files = await fg(Array.from(patterns), {
      cwd: this.options.path,
      ignore: excludePatterns,
      absolute: true,
      onlyFiles: true
    });

    return files;
  }

  private async scanFile(filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const content = await Bun.file(filePath).text();

      // Get rules that match this file
      const applicableRules = this.rules.filter(rule => {
        if (!rule.filePatterns) return true;
        return rule.filePatterns.some(pattern => {
          // Convert glob pattern to regex for matching
          // First escape dots, then handle glob patterns
          const regexPattern = pattern
            .replace(/\./g, '\\.')
            .replace(/\*\*/g, '.*')
            .replace(/(?<!\.)(\*)/g, '[^/]*');
          return new RegExp(regexPattern).test(filePath);
        });
      });

      // Apply each rule
      for (const rule of applicableRules) {
        if (rule.check) {
          const ruleFindings = rule.check(content, filePath);
          findings.push(...ruleFindings);
        } else if (rule.patterns) {
          // Simple pattern matching
          for (const pattern of rule.patterns) {
            let match;
            const regex = new RegExp(pattern.source, pattern.flags);
            const lines = content.split('\n');

            while ((match = regex.exec(content)) !== null) {
              const lineNum = content.substring(0, match.index).split('\n').length;
              findings.push({
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                category: rule.category,
                message: rule.description,
                filePath,
                line: lineNum,
                codeSnippet: lines[lineNum - 1]?.trim(),
                remediation: rule.remediation,
                references: rule.references
              });
            }
          }
        }
      }
    } catch (error) {
      if (this.options.verbose) {
        console.error(`Error scanning ${filePath}:`, error);
      }
    }

    return findings;
  }

  private sortFindings(findings: Finding[]): Finding[] {
    const severityOrder: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };

    return findings.sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      return a.filePath.localeCompare(b.filePath);
    });
  }

  private generateSummary(findings: Finding[]) {
    const byCategory: Record<RuleCategory, number> = {
      storage: 0,
      network: 0,
      authentication: 0,
      secrets: 0,
      cryptography: 0,
      logging: 0,
      capacitor: 0,
      debug: 0,
      android: 0,
      ios: 0,
      config: 0,
      webview: 0,
      permissions: 0
    };

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    for (const finding of findings) {
      byCategory[finding.category]++;

      switch (finding.severity) {
        case 'critical': critical++; break;
        case 'high': high++; break;
        case 'medium': medium++; break;
        case 'low': low++; break;
        case 'info': info++; break;
      }
    }

    return {
      total: findings.length,
      critical,
      high,
      medium,
      low,
      info,
      byCategory
    };
  }

  static getRuleCount(): number {
    return ruleCount;
  }
}
