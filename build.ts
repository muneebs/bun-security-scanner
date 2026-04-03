import { rmSync } from 'node:fs';

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
} as const;

const pkg = await Bun.file('./package.json').json();
const version = pkg.version as string;
const buildTime = new Date().toISOString();

console.log(
  `\n  ${c.cyan}${c.bold}@nebzdev/bun-security-scanner${c.reset} ${c.dim}v${version}${c.reset}\n`
);

// Clean previous output
rmSync('./dist', { recursive: true, force: true });

const start = performance.now();
process.stdout.write(`  ${c.cyan}▸${c.reset} Bundling...`);

const result = await Bun.build({
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  naming: 'index.js',
  target: 'bun',
  format: 'esm',
  minify: true,
});

const elapsed = ((performance.now() - start) / 1000).toFixed(2);

if (!result.success) {
  console.log(` ${c.red}${c.bold}FAILED${c.reset}\n`);
  for (const log of result.logs) {
    console.error(`  ${c.red}✗${c.reset} ${log}`);
  }
  console.error(`\n  ${c.bgRed}${c.white}${c.bold} BUILD FAILED ${c.reset}\n`);
  process.exit(1);
}

const sizeKB = (Bun.file('./dist/index.js').size / 1024).toFixed(1);

console.log(
  ` ${c.green}${c.bold}done${c.reset} ${c.dim}(${elapsed}s)${c.reset}`
);
console.log(`
  ${c.green}${c.bold}✓ Build succeeded${c.reset}

  ${c.dim}Output${c.reset}    ${c.white}dist/index.js${c.reset}  ${c.dim}(${sizeKB} KB)${c.reset}
  ${c.dim}Built at${c.reset}  ${c.white}${buildTime}${c.reset}
`);
