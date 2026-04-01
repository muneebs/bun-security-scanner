import type { SnykIssue } from './client';

export function severityLevel(issue: SnykIssue): 'fatal' | 'warn' {
  const level = issue.attributes.effective_severity_level;
  return level === 'critical' || level === 'high' ? 'fatal' : 'warn';
}

export function advisoryUrl(issue: SnykIssue): string {
  return `https://security.snyk.io/vuln/${issue.id}`;
}
