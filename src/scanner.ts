import { isFresh, readCache, writeCache } from './cache';
import { isResolvable } from './client';
import { startSpinner } from './display';
import { applyIgnoreList, type IgnoreList, loadIgnoreList } from './ignore';

export interface Backend {
  readonly name: string;
  readonly cacheFile: string;
  readonly ttl: number;
  readonly noCache: boolean;
  readonly failClosed: boolean;
  validateConfig?(): void;
  fetchAdvisories(
    packages: Bun.Security.Package[],
    onStatus: (message: string) => void
  ): Promise<Map<string, Bun.Security.Advisory[]>>;
}

export function createScanner(backend: Backend): Bun.Security.Scanner {
  return {
    version: '1',

    async scan({ packages }) {
      backend.validateConfig?.();

      const queryable = packages.filter(
        (p) => p.name && isResolvable(p.version)
      );
      if (queryable.length === 0) return [];

      const [cache, ignoreList] = await Promise.all([
        backend.noCache
          ? Promise.resolve({} as Awaited<ReturnType<typeof readCache>>)
          : readCache(backend.cacheFile),
        loadIgnoreList(),
      ]);

      const cachedAdvisories: Bun.Security.Advisory[] = [];
      const toQuery: Bun.Security.Package[] = [];

      for (const pkg of queryable) {
        const entry = cache[`${pkg.name}@${pkg.version}`];
        if (entry && isFresh(entry, backend.ttl)) {
          cachedAdvisories.push(...entry.advisories);
        } else {
          toQuery.push(pkg);
        }
      }

      if (toQuery.length === 0)
        return applyIgnores(cachedAdvisories, ignoreList);

      const hitCount = queryable.length - toQuery.length;
      const spinner = startSpinner(
        hitCount > 0
          ? `Scanning ${toQuery.length} packages via ${backend.name} (${hitCount} cached)...`
          : `Scanning ${queryable.length} packages via ${backend.name}...`
      );

      try {
        const advisoryMap = await backend.fetchAdvisories(toQuery, (msg) =>
          spinner.update(msg)
        );

        spinner.stop();

        for (const [key, advisories] of advisoryMap) {
          cache[key] = { advisories, cachedAt: Date.now() };
        }
        if (!backend.noCache) void writeCache(cache, backend.cacheFile);

        return applyIgnores(
          [...cachedAdvisories, ...[...advisoryMap.values()].flat()],
          ignoreList
        );
      } catch (err) {
        spinner.stop();

        if (backend.failClosed) {
          throw new Error(
            `${backend.name} scan failed: ${err instanceof Error ? err.message : err}`
          );
        }

        process.stderr.write(
          `\n${backend.name} scan failed (${err instanceof Error ? err.message : err}), skipping.\n`
        );
        return applyIgnores(cachedAdvisories, ignoreList);
      }
    },
  };
}

/**
 * Apply the ignore list to a set of advisories:
 * - `fatal` advisories that are ignored are downgraded to `warn`
 * - `warn` advisories that are ignored are dropped entirely
 * - Both cases are logged to stderr so they remain visible in CI output
 */
function applyIgnores(
  advisories: Bun.Security.Advisory[],
  ignoreList: IgnoreList
): Bun.Security.Advisory[] {
  if (ignoreList.entries.length === 0) return advisories;

  const result: Bun.Security.Advisory[] = [];

  for (const advisory of advisories) {
    const decision = applyIgnoreList(advisory, ignoreList);

    if (decision.action === 'keep') {
      result.push(advisory);
    } else if (decision.action === 'downgrade') {
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] Downgrading ${advisory.package} fatal advisory to warn (${advisory.url}) — ${decision.reason}\n`
      );
      result.push({ ...advisory, level: 'warn' });
    } else {
      // drop
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] Suppressing ${advisory.package} advisory (${advisory.url}) — ${decision.reason}\n`
      );
    }
  }

  return result;
}
