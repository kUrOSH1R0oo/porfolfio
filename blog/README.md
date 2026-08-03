# blog/

Works exactly like `writeup/` — every `.md` file dropped here is automatically
detected and shown as a card in the **Blog** section. Clicking a card opens
the full post in a modal, rendered from Markdown.

See `writeup/README.md` for the full front matter reference and an
explanation of how the auto-detection build step works (short version: a
build script regenerates `manifest.json`, so there's still no backend/server
at runtime).

Quick template:

```markdown
---
title: My Post Title
date: 2026-03-01
excerpt: A short teaser shown on the card.
cover: ../uploads/my-post-cover.png
tags: ctf, thoughts
---

Write your post here in normal Markdown. Reference images with
`../uploads/filename.png`.
```

`example-post.md` is a placeholder — delete it once you add your own posts.
