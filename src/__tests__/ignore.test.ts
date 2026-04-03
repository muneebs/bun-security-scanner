import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { applyIgnoreList, loadIgnoreList, type IgnoreList } from '../ignore';

// ── helpers ──────────────────────────────────────────────────────────────────

function advisory(
  pkg: string,
  level: 'fatal' | 'warn',
  url: string
): Bun.Security.Advisory {
  return {
    package: pkg,
    level,
    description: 'Test advisory',
    url,
  };
}

function ignoreList(...entries: IgnoreList['entries']): IgnoreList {
  return { entries };
}

const FUTURE = '2099-12-31';
const PAST = '2000-01-01';

// ── applyIgnoreList ───────────────────────────────────────────────────────────

describe('applyIgnoreList', () => {
  test('keeps advisory when ignore list is empty', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList()
    );
    expect(result.action).toBe('keep');
  });

  test('keeps advisory when package name does not match', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'minimist',
        advisories: ['GHSA-aaa-bbb-cccc'],
        reason: 'not our package',
      })
    );
    expect(result.action).toBe('keep');
  });

  test('keeps advisory when advisory ID does not match', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-xxx-yyy-zzzz'],
        reason: 'different advisory',
      })
    );
    expect(result.action).toBe('keep');
  });

  test('downgrades fatal advisory to warn when matched', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-aaa-bbb-cccc'],
        reason: 'only affects cloneDeep',
      })
    );
    expect(result.action).toBe('downgrade');
    if (result.action === 'downgrade') {
      expect(result.reason).toBe('only affects cloneDeep');
    }
  });

  test('drops warn advisory when matched', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'warn',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-aaa-bbb-cccc'],
        reason: 'transitive only',
      })
    );
    expect(result.action).toBe('drop');
    if (result.action === 'drop') {
      expect(result.reason).toBe('transitive only');
    }
  });

  test('wildcard matches any advisory ID for the package', () => {
    const result = applyIgnoreList(
      advisory(
        'minimist',
        'fatal',
        'https://nvd.nist.gov/vuln/detail/CVE-2021-44906'
      ),
      ignoreList({
        package: 'minimist',
        advisories: ['*'],
        reason: 'transitive only',
      })
    );
    expect(result.action).toBe('downgrade');
  });

  test('matching is case-insensitive for advisory IDs', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['ghsa-aaa-bbb-cccc'],
        reason: 'lowercase in ignore file',
      })
    );
    expect(result.action).toBe('downgrade');
  });

  test('keeps advisory when entry has expired', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-aaa-bbb-cccc'],
        reason: 'was suppressed',
        expires: PAST,
      })
    );
    expect(result.action).toBe('keep');
  });

  test('matches advisory when entry has a future expiry', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'warn',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-aaa-bbb-cccc'],
        reason: 'still active',
        expires: FUTURE,
      })
    );
    expect(result.action).toBe('drop');
  });

  test('uses fallback reason when entry has no reason', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList({
        package: 'lodash',
        advisories: ['GHSA-aaa-bbb-cccc'],
      })
    );
    expect(result.action).toBe('downgrade');
    if (result.action === 'downgrade') {
      expect(result.reason).toBe('(no reason provided)');
    }
  });

  test('extracts advisory ID from NVD URL', () => {
    const result = applyIgnoreList(
      advisory(
        'pkg',
        'fatal',
        'https://nvd.nist.gov/vuln/detail/CVE-2021-44906'
      ),
      ignoreList({
        package: 'pkg',
        advisories: ['CVE-2021-44906'],
        reason: 'accepted risk',
      })
    );
    expect(result.action).toBe('downgrade');
  });

  test('uses first matching entry', () => {
    const result = applyIgnoreList(
      advisory(
        'lodash',
        'fatal',
        'https://ghsa.github.com/advisories/GHSA-aaa-bbb-cccc'
      ),
      ignoreList(
        {
          package: 'lodash',
          advisories: ['GHSA-aaa-bbb-cccc'],
          reason: 'first entry',
        },
        {
          package: 'lodash',
          advisories: ['*'],
          reason: 'second entry',
        }
      )
    );
    expect(result.action).toBe('downgrade');
    if (result.action === 'downgrade') {
      expect(result.reason).toBe('first entry');
    }
  });
});

// ── loadIgnoreList ────────────────────────────────────────────────────────────

describe('loadIgnoreList', () => {
  let fileSpy: ReturnType<typeof spyOn<typeof Bun, 'file'>>;
  let ignoreFileContent: string | null = null;

  beforeEach(() => {
    ignoreFileContent = null;
    const origBunFile = Bun.file.bind(Bun);
    fileSpy = spyOn(Bun, 'file');
    fileSpy.mockImplementation(((path: unknown, opts?: BlobPropertyBag) => {
      if (path === '.bun-security-ignore') {
        if (ignoreFileContent === null) {
          return {
            text: async () => {
              throw new Error('ENOENT');
            },
          } as unknown as ReturnType<typeof Bun.file>;
        }
        const content = ignoreFileContent;
        return {
          text: async () => content,
        } as unknown as ReturnType<typeof Bun.file>;
      }
      if (typeof path === 'string') {
        return {
          text: async () => {
            throw new Error('ENOENT');
          },
        } as unknown as ReturnType<typeof Bun.file>;
      }
      return origBunFile(path as Parameters<typeof Bun.file>[0], opts);
    }) as typeof Bun.file);
  });

  afterEach(() => {
    fileSpy.mockRestore();
  });

  test('returns empty list when ignore file does not exist', async () => {
    // ignoreFileContent stays null → ENOENT
    const list = await loadIgnoreList();
    expect(list.entries).toHaveLength(0);
  });

  test('parses a valid ignore file with one entry', async () => {
    ignoreFileContent = `
[[ignore]]
package = "lodash"
advisories = ["GHSA-aaa-bbb-cccc"]
reason = "cloneDeep not used"
expires = "${FUTURE}"
`;

    const list = await loadIgnoreList();
    expect(list.entries).toHaveLength(1);
    expect(list.entries[0]).toMatchObject({
      package: 'lodash',
      advisories: ['GHSA-aaa-bbb-cccc'],
      reason: 'cloneDeep not used',
      expires: FUTURE,
    });
  });

  test('parses multiple [[ignore]] entries', async () => {
    ignoreFileContent = `
[[ignore]]
package = "lodash"
advisories = ["GHSA-aaa-bbb-cccc"]
reason = "first"

[[ignore]]
package = "minimist"
advisories = ["*"]
reason = "second"
`;

    const list = await loadIgnoreList();
    expect(list.entries).toHaveLength(2);
    expect(list.entries[0].package).toBe('lodash');
    expect(list.entries[1].package).toBe('minimist');
  });

  test('parses wildcard advisory', async () => {
    ignoreFileContent = `
[[ignore]]
package = "minimist"
advisories = ["*"]
reason = "transitive only"
`;

    const list = await loadIgnoreList();
    expect(list.entries[0]?.advisories).toEqual(['*']);
  });

  test('ignores comment lines and blank lines', async () => {
    ignoreFileContent = `
# This is a comment

[[ignore]]
# Another comment
package = "lodash"
advisories = ["GHSA-aaa"]
reason = "ok"
`;

    const list = await loadIgnoreList();
    expect(list.entries).toHaveLength(1);
  });

  test('still returns entry when reason is missing', async () => {
    ignoreFileContent = `
[[ignore]]
package = "lodash"
advisories = ["GHSA-aaa"]
`;

    const list = await loadIgnoreList();
    expect(list.entries).toHaveLength(1);
    expect(list.entries[0]?.reason).toBeUndefined();
  });
});
