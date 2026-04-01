import { CACHE_FILE, FAIL_CLOSED, NO_CACHE } from './config';
import { validateConfig, batchFetchIssues } from './client';
import { severityLevel, advisoryUrl } from './severity';
import { createScanner, type Backend } from '../scanner';

const backend: Backend = {
  name: 'Snyk',
  cacheFile: CACHE_FILE,
  noCache: NO_CACHE,
  failClosed: FAIL_CLOSED,
  validateConfig,

  async fetchAdvisories(packages, onStatus) {
    const issueMap = await batchFetchIssues(packages, (done, total) => {
      onStatus(`Scanning packages via Snyk (${done}/${total})...`);
    });

    const result = new Map<string, Bun.Security.Advisory[]>();
    for (const pkg of packages) {
      const key = `${pkg.name}@${pkg.version}`;
      const issues = issueMap.get(key) ?? [];
      result.set(
        key,
        issues.map((issue) => ({
          level: severityLevel(issue),
          package: pkg.name,
          url: advisoryUrl(issue),
          description: issue.attributes.title,
        })),
      );
    }

    return result;
  },
};

export { backend };
export const scanner = createScanner(backend);
