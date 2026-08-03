# writeup/

Every `.md` file you place in this folder is automatically detected and shown
as a card in the **Write-Ups** section of the site, automatically grouped
under a category heading (B2R, Jeopardy, Linux, Windows, or whatever you set).
Clicking a card opens the full write-up on its own dedicated page
(`entry.html`), rendered from Markdown with syntax-highlighted code blocks —
no HTML editing required.

## Adding a new write-up

1. Create a new file, e.g. `writeup/htb-forgotten.md`.
2. Start it with front matter, then write the rest in plain Markdown:

```markdown
---
title: HackTheBox Forgotten — Writeup
date: 2026-02-01
excerpt: One or two sentences describing the box / vuln chain, shown on the card.
cover: ../uploads/forgotten-cover.png
category: B2R
tags: web, htb, ssrf
---

## Recon

Your write-up content goes here. Standard Markdown is supported: headings,
lists, **bold**, _italics_, `inline code`, fenced code blocks (with syntax
highlighting), blockquotes, tables, and images.

![Nmap output](../uploads/forgotten-nmap.png)
```

3. Put any screenshots/images this file references into `../uploads/`.
4. Commit and push. The next build regenerates `manifest.json` and the card
   appears automatically, sorted into its category — you don't need to touch
   `index.html`, `script.js`, or `styles.css`.

## Front matter fields

| Field      | Required | Notes                                                         |
|------------|----------|----------------------------------------------------------------|
| `title`    | No       | Falls back to a title-cased version of the filename.          |
| `date`     | No       | `YYYY-MM-DD`. Used to sort cards newest-first.                  |
| `excerpt`  | No       | Falls back to an auto-generated summary of the first ~160 chars.|
| `cover`    | No       | Path to an image in `../uploads/`, shown at the top of the card.|
| `category` | No       | Groups the write-up under a heading, e.g. `B2R`, `Jeopardy`, `Linux`, `Windows`. Any value works — cards without one land under "Uncategorized". |
| `tags`     | No       | Comma-separated, e.g. `web, htb, ssrf`.                         |
| `slug`     | No       | Falls back to a slugified filename. Used internally.           |

## How the "auto-detect" works (read this if hosting on GitHub/Cloudflare Pages)

Static sites can't ask the browser to "list the files in this folder" — there's
no server to answer that. Instead, a tiny Node script
(`scripts/generate-manifest.js`) scans this folder at **build time** and writes
`writeup/manifest.json`, which the front-end fetches to know what exists. This
already runs automatically via:

- **GitHub Pages** — the included GitHub Actions workflow
  (`.github/workflows/deploy.yml`) runs the script on every push to `main`.
- **Cloudflare Pages** — set the build command to
  `node scripts/generate-manifest.js` (see root `README.md`).

So in practice: add a `.md` file, push, and it shows up. No backend server is
ever involved — the script only runs during the build/deploy step.

`example-writeup.md` is a placeholder so you can see the system working out of
the box. Delete it whenever you like.
