(function () {
    const SOURCES = {
        writeup: {
            folder: 'writeup',
            gridId: 'writeupGrid',
            readLabel: 'Read →',
            emptyMessage: 'No local write-ups yet — drop a .md file in /writeup to get started.'
        },
        blog: {
            folder: 'blog',
            gridId: 'blogGrid',
            readLabel: 'Read →',
            emptyMessage: 'No posts yet — drop a .md file in /blog to get started.'
        }
    };

    const CATEGORY_ORDER = ['B2R', 'Jeopardy', 'Linux', 'Windows'];

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str == null ? '' : String(str);
        return div.innerHTML;
    }

    function slugifyCategory(name) {
        return String(name)
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/(^-+|-+$)/g, '') || 'uncategorized';
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

    function coverMarkup(entry) {
        if (!entry.cover) return '';
        return `<div class="content-card-cover"><img src="${escapeHtml(entry.cover)}" alt="" loading="lazy"></div>`;
    }

    function entryHref(source, entry) {
        const slug = entry.slug || entry.file;
        return `entry.html?type=${encodeURIComponent(source)}&slug=${encodeURIComponent(slug)}`;
    }

    function cardMarkup(entry, source) {
        return `
            <div class="content-card">
                ${coverMarkup(entry)}
                ${entry.date ? `<span class="content-card-date">${escapeHtml(formatDate(entry.date))}</span>` : ''}
                <h3>${escapeHtml(entry.title)}</h3>
                ${entry.tags && entry.tags.length ? `<div class="content-card-tags">${tagsMarkup(entry.tags)}</div>` : ''}
                <p>${escapeHtml(entry.excerpt)}</p>
                <a class="content-card-read" href="${entryHref(source, entry)}">
                    ${escapeHtml(SOURCES[source].readLabel)}
                </a>
            </div>`;
    }

    function groupByCategory(entries) {
        const groups = new Map();
        entries.forEach((entry) => {
            const name = (entry.category || '').trim() || 'Uncategorized';
            if (!groups.has(name)) groups.set(name, []);
            groups.get(name).push(entry);
        });
        return groups;
    }

    function orderedCategoryNames(groups) {
        const names = Array.from(groups.keys());
        const known = CATEGORY_ORDER.filter((c) => names.includes(c));
        const rest = names
            .filter((n) => n !== 'Uncategorized' && !known.includes(n))
            .sort((a, b) => a.localeCompare(b));
        const tail = names.includes('Uncategorized') ? ['Uncategorized'] : [];
        return [...known, ...rest, ...tail];
    }

    function categoryPillsMarkup(orderedNames, groups) {
        if (orderedNames.length < 2) return '';
        const pills = orderedNames
            .map((name) => `<a class="category-pill" href="#cat-${slugifyCategory(name)}">${escapeHtml(name)} <span class="category-pill-count">${groups.get(name).length}</span></a>`)
            .join('');
        return `<div class="category-pills">${pills}</div>`;
    }

    function renderGrid(source, entries) {
        const grid = document.getElementById(SOURCES[source].gridId);
        if (!grid) return;

        if (!entries.length) {
            grid.innerHTML = `<p class="dynamic-empty">${escapeHtml(SOURCES[source].emptyMessage)}</p>`;
            return;
        }

        const groups = groupByCategory(entries);
        const orderedNames = orderedCategoryNames(groups);
        const isFlat = orderedNames.length === 1 && orderedNames[0] === 'Uncategorized';

        if (isFlat) {
            grid.innerHTML = `<div class="content-card-grid">${entries.map((e) => cardMarkup(e, source)).join('')}</div>`;
            return;
        }

        const pills = categoryPillsMarkup(orderedNames, groups);
        const sections = orderedNames.map((name) => {
            const items = groups.get(name);
            return `
                <div class="category-section" id="cat-${slugifyCategory(name)}">
                    <h3 class="category-heading">${escapeHtml(name)} <span class="category-count">${items.length}</span></h3>
                    <div class="content-card-grid">${items.map((e) => cardMarkup(e, source)).join('')}</div>
                </div>`;
        }).join('');

        grid.innerHTML = pills + sections;
    }

    function renderError(source, message) {
        const grid = document.getElementById(SOURCES[source].gridId);
        if (!grid) return;
        grid.innerHTML = `<p class="dynamic-error">${escapeHtml(message)}</p>`;
    }

    async function loadSource(source) {
        const { folder, gridId } = SOURCES[source];
        if (!document.getElementById(gridId)) return; // this page doesn't render this grid
        try {
            const res = await fetch(`${folder}/manifest.json`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const entries = await res.json();
            renderGrid(source, Array.isArray(entries) ? entries : []);
        } catch (err) {
            renderError(
                source,
                `Couldn't load ${folder}/manifest.json. If you're viewing this over file://, serve the folder with a local web server. Otherwise run "node scripts/generate-manifest.js" (or push — the GitHub Actions workflow runs it for you).`
            );
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        Object.keys(SOURCES).forEach(loadSource);
    });
})();
