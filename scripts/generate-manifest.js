#!/usr/bin/env node
/**
 * generate-manifest.js
 * ---------------------------------------------------------------------------
 * Scans the /writeup and /blog folders for Markdown (.md) files, reads their
 * front matter, and writes a manifest.json into each folder describing every
 * entry (title, date, excerpt, cover image, tags, filename).
 *
 * The site's front-end (content.js) fetches manifest.json to know which
 * write-ups / blog posts exist and renders a card for each one automatically.
 * This is what makes "drop a .md file in the folder and it just shows up" work
 * on a fully static host (GitHub Pages / Cloudflare Pages) with no backend or
 * server-side directory listing involved.
 *
 * Run manually:   node scripts/generate-manifest.js
 * Run on deploy:  wired up automatically via the GitHub Actions workflow in
 *                 .github/workflows/deploy.yml, or as the Cloudflare Pages
 *                 "Build command".
 *
 * No npm dependencies required — pure Node.js `fs`/`path`.
 * ---------------------------------------------------------------------------
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const FOLDERS = ['writeup', 'blog'];
const IGNORED_FILES = new Set(['readme.md', 'template.md']);

function parseFrontMatter(raw) {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { data: {}, content: raw };

  const [, block, content] = match;
  const data = {};

  block.split(/\r?\n/).forEach((line) => {
    const idx = line.indexOf(':');
    if (idx === -1) return;
    const key = line.slice(0, idx).trim();
    let value = line.slice(idx + 1).trim();
    value = value.replace(/^["']|["']$/g, ''); // strip wrapping quotes
    data[key] = value;
  });

  return { data, content };
}

function slugify(filename) {
  return filename
    .replace(/\.md$/i, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-+|-+$)/g, '');
}

function titleCaseFromSlug(slug) {
  return slug.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function excerptFrom(content, maxLen = 160) {
  const plain = content
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[#>*_`~]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (plain.length <= maxLen) return plain;
  return `${plain.slice(0, maxLen).trim()}…`;
}

function buildManifestFor(folder) {
  const dir = path.join(ROOT, folder);

  if (!fs.existsSync(dir)) {
    console.log(`[manifest] "${folder}/" not found, skipping.`);
    return;
  }

  const files = fs
    .readdirSync(dir)
    .filter((f) => f.toLowerCase().endsWith('.md') && !IGNORED_FILES.has(f.toLowerCase()));

  const entries = files.map((file) => {
    const raw = fs.readFileSync(path.join(dir, file), 'utf8');
    const { data, content } = parseFrontMatter(raw);
    const slug = data.slug || slugify(file);

    return {
      slug,
      file,
      title: data.title || titleCaseFromSlug(slug),
      date: data.date || '',
      excerpt: data.excerpt || excerptFrom(content),
      cover: data.cover || '',
      category: data.category || '',
      tags: data.tags
        ? data.tags.split(',').map((t) => t.trim()).filter(Boolean)
        : [],
    };
  });

  // Newest first. Entries without a date sort to the end.
  entries.sort((a, b) => {
    if (!a.date && !b.date) return a.title.localeCompare(b.title);
    if (!a.date) return 1;
    if (!b.date) return -1;
    return b.date.localeCompare(a.date);
  });

  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify(entries, null, 2) + '\n'
  );

  console.log(`[manifest] ${folder}/manifest.json — ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`);
}

FOLDERS.forEach(buildManifestFor);
