# uploads/

Drop any image referenced by your write-ups or blog posts in this folder
(screenshots, diagrams, cover images, etc.).

This folder is **not** scanned or treated as content itself — it's just where
image files live so that `writeup/*.md` and `blog/*.md` can point to them with
a relative path:

```markdown
![Nmap scan results](../uploads/nmap-scan.png)
```

```yaml
---
title: My Write-Up
cover: ../uploads/my-cover.png
---
```

Because `writeup/`, `blog/`, and `uploads/` are sibling folders, the `../uploads/`
prefix works no matter what domain or sub-path the site is deployed under
(GitHub Pages project sites, Cloudflare Pages, a custom domain, etc.) — an
absolute path like `/uploads/...` would break on GitHub Pages project sites
served from `username.github.io/repo-name/`.

`placeholder-cover.svg` is only a demo asset used by the example write-up/blog
post — feel free to delete it once you add your own images.
