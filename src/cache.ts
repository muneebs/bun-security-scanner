import { CACHE_FILE, CACHE_TTL_MS } from './config';

export interface CacheEntry {
  advisories: Bun.Security.Advisory[];
  cachedAt: number;
}

type Cache = Record<string, CacheEntry>;

export async function readCache(): Promise<Cache> {
  try {
    return JSON.parse(await Bun.file(CACHE_FILE).text());
  } catch {
    return {};
  }
}

export async function writeCache(cache: Cache): Promise<void> {
  try {
    await Bun.write(CACHE_FILE, JSON.stringify(cache));
  } catch {}
}

export function isFresh(entry: CacheEntry): boolean {
  return Date.now() - entry.cachedAt < CACHE_TTL_MS;
}
