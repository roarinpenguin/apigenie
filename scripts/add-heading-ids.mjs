// Post-process marked's HTML to add GitHub-style anchor ids on headings so the
// in-document TOC links (`#slug`) resolve — which lets headless Chrome emit
// clickable internal links in the PDF. Pure Node (no deps) to avoid ESM
// resolution issues under `npx`.
//
// Slug algorithm matches the *collapsing* slugger the guide's TOC was authored
// against: lowercase → drop punctuation (keep word/space/hyphen) → spaces to
// hyphens → collapse repeats → dedupe with -1, -2 suffixes. Verified against
// existing anchors, e.g. "# Part IV — Have Data Pipelines? Onboard 12 sources
// in 10 minutes!" → "part-iv-have-data-pipelines-onboard-12-sources-in-10-minutes".
import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) { console.error('usage: add-heading-ids.mjs <file.html>'); process.exit(2); }

const seen = new Map();

function decodeEntities(s) {
  return s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

function slug(text) {
  let s = decodeEntities(text)
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
  if (!s) return s;
  if (seen.has(s)) {
    const n = seen.get(s) + 1;
    seen.set(s, n);
    s = `${s}-${n}`;
  } else {
    seen.set(s, 0);
  }
  return s;
}

let html = readFileSync(file, 'utf8');
html = html.replace(/<h([1-6])([^>]*)>([\s\S]*?)<\/h\1>/g, (m, lvl, attrs, inner) => {
  if (/\bid\s*=/.test(attrs)) return m;               // respect an existing id
  const text = inner.replace(/<[^>]+>/g, '');          // visible text only
  const id = slug(text);
  if (!id) return m;
  return `<h${lvl}${attrs} id="${id}">${inner}</h${lvl}>`;
});
writeFileSync(file, html);
