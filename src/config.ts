export const OSV_API_BASE = Bun.env.OSV_API_BASE ?? 'https://api.osv.dev/v1';
// Hard limit enforced by the OSV API — exceeding it returns 400 "Too many queries".
export const OSV_BATCH_SIZE = 1000;
export const FETCH_TIMEOUT_MS = Number(Bun.env.OSV_TIMEOUT_MS) || 10_000;
export const PREFERRED_REF_TYPES = ['ADVISORY', 'WEB', 'ARTICLE'] as const;
export const CACHE_FILE = Bun.env.OSV_CACHE_FILE ?? '.osv.lock';
const _osvCacheTtl = Number(Bun.env.OSV_CACHE_TTL_MS);
export const CACHE_TTL_MS =
  Number.isFinite(_osvCacheTtl) && _osvCacheTtl >= 0
    ? _osvCacheTtl
    : 24 * 60 * 60 * 1000;

// When true, network failures throw and cancel installation rather than failing open.
export const FAIL_CLOSED = Bun.env.OSV_FAIL_CLOSED === 'true';
export const NO_CACHE = Bun.env.OSV_NO_CACHE === 'true';
