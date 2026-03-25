/**
 * PawSec extension build script (esbuild).
 *
 * Usage:
 *   node build.js                       → Chrome dev build  → dist-chrome/
 *   node build.js --prod                → Chrome production → dist-chrome/
 *   node build.js --firefox             → Firefox MV2 dev   → dist-firefox/
 *   node build.js --firefox --prod      → Firefox MV2 prod  → dist-firefox/
 *   node build.js --edge                → Edge MV3 dev      → dist-edge/
 *   node build.js --edge    --prod      → Edge MV3 prod     → dist-edge/
 *
 *   node build.js           --package   → Chrome zip  → pawsec-v1.0.0-chrome.zip
 *   node build.js --firefox --package   → Firefox zip → pawsec-v1.0.0-firefox.zip
 *   node build.js --edge    --package   → Edge zip    → pawsec-v1.0.0-edge.zip
 */

import esbuild from 'esbuild';
import {
  mkdirSync, readdirSync, readFileSync, copyFileSync,
  existsSync, writeFileSync,
} from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dir   = dirname(fileURLToPath(import.meta.url));
const args    = process.argv.slice(2);
const isFF    = args.includes('--firefox');
const isEdge  = args.includes('--edge');
const isProd  = args.includes('--prod') || args.includes('--package');
const doPkg   = args.includes('--package');

const browser = isFF ? 'firefox' : isEdge ? 'edge' : 'chrome';

// Output directory per browser.
// Chrome writes to both 'dist/' and 'dist-chrome/' so both stay in sync.
// Firefox and Edge write to their own dirs so all three can coexist.
const DIST_MAP = { chrome: 'dist', firefox: 'dist-firefox', edge: 'dist-edge' };
const DIST     = resolve(__dir, DIST_MAP[browser]);
const VERSION  = JSON.parse(readFileSync(resolve(__dir, 'package.json'), 'utf8')).version;

// ─── esbuild options ──────────────────────────────────────────────────────────

const commonOpts = {
  bundle:    true,
  platform:  'browser',
  minify:    isProd,
  sourcemap: isProd ? false : 'inline',
  logLevel:  'info',
};

// Firefox MV2: IIFE for everything — background pages can't use ES modules.
// Chrome/Edge MV3: ESM for service worker ("type":"module"), IIFE for content/UI.
const ffOpts = {
  ...commonOpts,
  format: 'iife',
  target: ['firefox91'],
  inject: [resolve(__dir, 'src/compat/browser_compat.js')],
};

const swOpts = isFF
  ? ffOpts
  : { ...commonOpts, format: 'esm', target: ['chrome120'] };

const uiOpts = isFF
  ? ffOpts
  : { ...commonOpts, format: 'iife', target: ['chrome120'] };

// ─── Entry points ─────────────────────────────────────────────────────────────

const entries = [
  // Per-site bundles (each bundles all 5 JS analyzers + content_base)
  { in: 'src/content/sites/chatgpt.js',     out: join(DIST, 'sites/chatgpt.js'),             opts: uiOpts },
  { in: 'src/content/sites/claude.js',      out: join(DIST, 'sites/claude.js'),              opts: uiOpts },
  { in: 'src/content/sites/gemini.js',      out: join(DIST, 'sites/gemini.js'),              opts: uiOpts },
  { in: 'src/content/sites/perplexity.js',  out: join(DIST, 'sites/perplexity.js'),          opts: uiOpts },
  { in: 'src/content/sites/copilot.js',     out: join(DIST, 'sites/copilot.js'),             opts: uiOpts },
  { in: 'src/content/sites/grok.js',       out: join(DIST, 'sites/grok.js'),               opts: uiOpts },
  // Background (service worker / event page)
  { in: 'src/background/service_worker.js', out: join(DIST, 'background/service_worker.js'), opts: swOpts },
  // Popup + Settings
  { in: 'src/popup/popup.js',               out: join(DIST, 'popup/popup.js'),               opts: uiOpts },
  { in: 'src/settings/settings.js',         out: join(DIST, 'settings/settings.js'),         opts: uiOpts },
];

// Create output dirs
for (const e of entries) mkdirSync(dirname(e.out), { recursive: true });

// ─── Build ────────────────────────────────────────────────────────────────────

console.log(`\n🐾 PawSec build — ${browser} / ${isProd ? 'production' : 'development'}\n`);

await Promise.all(
  entries.map(e =>
    esbuild.build({ ...e.opts, entryPoints: [resolve(__dir, e.in)], outfile: e.out })
  )
);

// ─── Static assets ────────────────────────────────────────────────────────────

// Pick source manifest — all three have clean paths (no dist-*/ prefix):
//   Chrome  → manifest.chrome.json   (MV3)
//   Firefox → manifest.firefox.json  (MV2)
//   Edge    → manifest.edge.json     (MV3)
const manifestSrc = isFF
  ? resolve(__dir, 'manifest.firefox.json')
  : isEdge
    ? resolve(__dir, 'manifest.edge.json')
    : resolve(__dir, 'manifest.chrome.json');

const manifestContent = readFileSync(manifestSrc, 'utf8');

mkdirSync(DIST, { recursive: true });
writeFileSync(join(DIST, 'manifest.json'), manifestContent);

// HTML / CSS
const staticFiles = [
  ['src/popup/popup.html',       join(DIST, 'popup/popup.html')],
  ['src/popup/popup.css',        join(DIST, 'popup/popup.css')],
  ['src/settings/settings.html', join(DIST, 'settings/settings.html')],
  ['src/settings/settings.css',  join(DIST, 'settings/settings.css')],
];

for (const [src, dst] of staticFiles) {
  const srcPath = resolve(__dir, src);
  mkdirSync(dirname(dst), { recursive: true });
  if (existsSync(srcPath)) copyFileSync(srcPath, dst);
}

// Icons
const iconsDir = resolve(__dir, 'icons');
if (existsSync(iconsDir)) {
  const iconFiles = readdirSync(iconsDir);
  // Always write to the primary DIST folder
  const iconsDst = join(DIST, 'icons');
  mkdirSync(iconsDst, { recursive: true });
  for (const file of iconFiles) {
    copyFileSync(join(iconsDir, file), join(iconsDst, file));
  }
  // Keep dist-chrome/ in sync whenever a Chrome build runs
  if (browser === 'chrome') {
    const distChrome = resolve(__dir, 'dist-chrome', 'icons');
    if (existsSync(resolve(__dir, 'dist-chrome'))) {
      mkdirSync(distChrome, { recursive: true });
      for (const file of iconFiles) {
        copyFileSync(join(iconsDir, file), join(distChrome, file));
      }
    }
  }
}

console.log(`\n✅ Build complete → ${DIST_MAP[browser]}/`);

// ─── Package (zip) ────────────────────────────────────────────────────────────

if (doPkg) {
  const zipName = `pawsec-v${VERSION}-${browser}.zip`;
  console.log(`\n📦 Creating ${zipName}…`);

  const { execSync } = await import('child_process');
  try {
    if (process.platform === 'win32') {
      execSync(
        `powershell Compress-Archive -Force -Path "${DIST}\\*" -DestinationPath "${resolve(__dir, zipName)}"`,
        { stdio: 'inherit' }
      );
    } else {
      execSync(`cd "${DIST}" && zip -r "${resolve(__dir, zipName)}" .`, { stdio: 'inherit', shell: true });
    }
    console.log(`✅ Package ready: ${zipName}`);
  } catch (e) {
    console.error('Packaging failed:', e.message);
    process.exit(1);
  }
}
