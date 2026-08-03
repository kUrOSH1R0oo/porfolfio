(function () {
    const SOURCES = {
        writeup: { folder: 'writeup', listPage: 'writeups.html', listLabel: 'Write-Ups' },
        blog: { folder: 'blog', listPage: 'blog.html', listLabel: 'Blog' }
    };

    const els = {
        back: document.getElementById('entryBack'),
        cover: document.getElementById('entryCover'),
        title: document.getElementById('entryTitle'),
        date: document.getElementById('entryDate'),
        tags: document.getElementById('entryTags'),
        body: document.getElementById('entryBody'),
        toc: document.getElementById('entryToc'),
        tocInner: document.getElementById('entryTocInner'),
        progress: document.getElementById('entryProgress')
    };

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str == null ? '' : String(str);
        return div.innerHTML;
    }

    function formatDate(dateStr) {
        if (!dateStr) return '';
        const d = new Date(dateStr);
        if (Number.isNaN(d.getTime())) return dateStr;
        return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    }

    function tagsMarkup(tags) {
        if (!tags || !tags.length) return '';
        return tags.map((t) => `<span class="content-card-tag">${escapeHtml(t)}</span>`).join('');
    }

    function stripFrontMatter(raw) {
        const match = raw.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n?([\s\S]*)$/);
        return match ? match[1] : raw;
    }

    function showError(message) {
        if (els.body) {
            els.body.innerHTML = `<p class="entry-error">${escapeHtml(message)}</p>`;
        }
        if (els.title) els.title.textContent = 'Not found';
        if (els.toc) els.toc.style.display = 'none';
    }

    function buildToc() {
        if (!els.body || !els.tocInner) return;

        const headings = Array.from(els.body.querySelectorAll('h2, h3'));
        if (headings.length < 2) {
            if (els.toc) els.toc.style.display = 'none';
            return;
        }

        const usedIds = new Set();
        const links = headings.map((h, i) => {
            let id = h.id;
            if (!id) {
                id = h.textContent
                    .toLowerCase()
                    .replace(/[^a-z0-9]+/g, '-')
                    .replace(/(^-+|-+$)/g, '') || `section-${i}`;
                let unique = id;
                let n = 2;
                while (usedIds.has(unique)) {
                    unique = `${id}-${n++}`;
                }
                id = unique;
                h.id = id;
            }
            usedIds.add(id);
            const level = h.tagName === 'H3' ? ' toc-level-3' : '';
            return `<a href="#${id}" class="toc-link${level}" data-target="${id}">${escapeHtml(h.textContent)}</a>`;
        });

        els.tocInner.innerHTML = `<span class="entry-toc-label">On this page</span><nav>${links.join('')}</nav>`;

        const tocLinks = els.tocInner.querySelectorAll('.toc-link');
        const linkFor = new Map();
        tocLinks.forEach((a) => linkFor.set(a.dataset.target, a));

        const headingObserver = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    const link = linkFor.get(entry.target.id);
                    if (!link) return;
                    if (entry.isIntersecting) {
                        tocLinks.forEach((a) => a.classList.remove('active'));
                        link.classList.add('active');
                    }
                });
            },
            { rootMargin: '-15% 0px -70% 0px', threshold: 0 }
        );

        headings.forEach((h) => headingObserver.observe(h));
    }

    function initProgressBar() {
        if (!els.progress || !els.body) return;

        const update = () => {
            const rect = els.body.getBoundingClientRect();
            const total = rect.height - window.innerHeight;
            const scrolled = window.scrollY - (els.body.offsetTop || 0) + window.innerHeight * 0.2;
            const pct = total > 0 ? Math.min(100, Math.max(0, (scrolled / total) * 100)) : 0;
            els.progress.style.width = `${pct}%`;
        };

        window.addEventListener('scroll', update, { passive: true });
        window.addEventListener('resize', update);
        update();
    }

    function highlightCode() {
        if (window.hljs && els.body) {
            els.body.querySelectorAll('pre code').forEach((block) => window.hljs.highlightElement(block));
        }
    }

    async function init() {
        const params = new URLSearchParams(window.location.search);
        const type = params.get('type');
        const slug = params.get('slug');
        const source = SOURCES[type];

        if (els.back) {
            els.back.href = source ? source.listPage : 'index.html';
            els.back.textContent = source ? `← Back to ${source.listLabel}` : '← Back home';
        }

        if (!source || !slug) {
            showError('Missing or invalid link. Head back and pick an entry from the list.');
            return;
        }

        let entry;
        try {
            const res = await fetch(`${source.folder}/manifest.json`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const entries = await res.json();
            entry = (Array.isArray(entries) ? entries : []).find(
                (e) => e.slug === slug || e.file === slug
            );
        } catch (err) {
            showError(`Couldn't load ${source.folder}/manifest.json (${err.message}).`);
            return;
        }

        if (!entry) {
            showError("That entry couldn't be found. It may have been moved or removed.");
            return;
        }

        document.title = `${entry.title} — Kur0Sh1r0`;
        if (els.title) els.title.textContent = entry.title || '';
        if (els.date) els.date.textContent = entry.date ? formatDate(entry.date) : '';
        if (els.tags) els.tags.innerHTML = tagsMarkup(entry.tags);
        if (els.cover) {
            els.cover.innerHTML = entry.cover
                ? `<img src="${escapeHtml(entry.cover)}" alt="">`
                : '';
            els.cover.style.display = entry.cover ? '' : 'none';
        }
        if (els.body) els.body.innerHTML = '<p class="entry-loading">Loading…</p>';

        try {
            const res = await fetch(`${source.folder}/${entry.file}`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const raw = await res.text();
            const body = stripFrontMatter(raw);
            const html = window.marked ? window.marked.parse(body) : escapeHtml(body);
            if (els.body) {
                els.body.innerHTML = window.DOMPurify ? window.DOMPurify.sanitize(html) : html;
            }
            highlightCode();
            buildToc();
            initProgressBar();
        } catch (err) {
            showError(`Couldn't load this entry (${err.message}).`);
        }
    }

    document.addEventListener('DOMContentLoaded', init);
})();
