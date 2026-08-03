(() => {
    const AWAY_MESSAGES = [
        'Comeback here!',
        "Where are you going?",
        'I will hack you!',
        'Hey!!!'
    ];

    let savedTitle = document.title;

    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            savedTitle = document.title;
            document.title = AWAY_MESSAGES[Math.floor(Math.random() * AWAY_MESSAGES.length)];
        } else {
            document.title = savedTitle;
        }
    });
})();

(() => {
    const SEQUENCE = [
        'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown',
        'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight',
        'b', 'a'
    ];
    let progress = 0;
    let toastTimeout;

    const showToast = (message) => {
        let toast = document.querySelector('.egg-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.className = 'egg-toast';
            document.body.appendChild(toast);
        }
        toast.textContent = message;
        requestAnimationFrame(() => toast.classList.add('visible'));
        clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => toast.classList.remove('visible'), 3200);
    };

    document.addEventListener('keydown', (e) => {
        const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
        progress = key === SEQUENCE[progress] ? progress + 1 : (key === SEQUENCE[0] ? 1 : 0);

        if (progress === SEQUENCE.length) {
            progress = 0;
            showToast("You found it. Achievement unlocked: nosy hacker 🕵️");
        }
    });
})();

document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    const closeMenu = () => {
        navLinks.classList.remove('active');
        hamburger.setAttribute('aria-expanded', 'false');
    };

    hamburger.addEventListener('click', () => {
        const isOpen = navLinks.classList.toggle('active');
        hamburger.setAttribute('aria-expanded', String(isOpen));
    });

    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', closeMenu);
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMenu();
    });

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const targetId = this.getAttribute('href');
            const target = document.querySelector(targetId);
            if (!target) return;
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth' });
            history.pushState(null, '', targetId);
        });
    });

    if (window.particlesJS) {
        particlesJS('particles-js', {
            particles: {
                number: { value: 60, density: { enable: true, value_area: 900 } },
                color: { value: '#00ff7f' },
                shape: { type: 'circle' },
                opacity: { value: 0.4, random: true },
                size: { value: 2.5, random: true },
                line_linked: { enable: true, distance: 150, color: '#00ff7f', opacity: 0.25, width: 1 },
                move: { enable: true, speed: 1.4, direction: 'none', random: false, straight: false, out_mode: 'out', bounce: false }
            },
            interactivity: {
                detect_on: 'canvas',
                events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' }, resize: true },
                modes: { repulse: { distance: 90, duration: 0.4 }, push: { particles_nb: 3 } }
            },
            retina_detect: true
        });
    }

    const sections = document.querySelectorAll('section');
    const revealObserver = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                obs.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });

    sections.forEach(section => revealObserver.observe(section));

    const navAnchors = document.querySelectorAll('.nav-links a');
    const navMap = new Map();
    navAnchors.forEach(a => navMap.set(a.getAttribute('href').slice(1), a));

    const activeObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            const link = navMap.get(entry.target.id);
            if (!link) return;
            if (entry.isIntersecting) {
                navAnchors.forEach(a => a.classList.remove('active'));
                link.classList.add('active');
            }
        });
    }, { rootMargin: '-45% 0px -50% 0px', threshold: 0 });

    sections.forEach(section => activeObserver.observe(section));

    const toTop = document.getElementById('toTop');
    if (toTop) {
        window.addEventListener('scroll', () => {
            toTop.classList.toggle('visible', window.scrollY > 600);
        }, { passive: true });

        toTop.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    const lightbox = document.getElementById('lightbox');

    if (lightbox) {
        const lightboxImg = document.getElementById('lightboxImg');
        const lightboxTitle = document.getElementById('lightboxTitle');
        const lightboxDesc = document.getElementById('lightboxDesc');
        const lightboxDownload = document.getElementById('lightboxDownload');
        let lastFocused = null;

        const openLightbox = (badge) => {
            const { full, title, desc } = badge.dataset;
            lightboxImg.src = full;
            lightboxImg.alt = title || 'Credential badge';
            lightboxTitle.textContent = title || '';
            lightboxDesc.textContent = desc || '';
            lightboxDownload.href = full;

            lastFocused = document.activeElement;
            lightbox.setAttribute('aria-hidden', 'false');
            document.body.style.overflow = 'hidden';
            lightbox.querySelector('.lightbox-close').focus();
        };

        const closeLightbox = () => {
            lightbox.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = '';
            lightboxImg.src = '';
            if (lastFocused) lastFocused.focus();
        };

        document.querySelectorAll('.cert-badge').forEach(badge => {
            badge.addEventListener('click', () => openLightbox(badge));
        });

        lightbox.querySelectorAll('[data-close]').forEach(el => {
            el.addEventListener('click', closeLightbox);
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && lightbox.getAttribute('aria-hidden') === 'false') {
                closeLightbox();
            }
        });
    }

    const certScroll = document.getElementById('certScroll');

    if (certScroll) {
        const VISIBLE_COUNT = 2;

        const sizeCertScroll = () => {
            const items = certScroll.querySelectorAll('.cert-badges');
            if (!items.length) return;

            const count = Math.min(VISIBLE_COUNT, items.length);
            let totalHeight = 0;

            for (let i = 0; i < count; i++) {
                const item = items[i];
                const style = window.getComputedStyle(item);
                const marginTop = parseFloat(style.marginTop) || 0;
                const marginBottom = parseFloat(style.marginBottom) || 0;
                totalHeight += item.getBoundingClientRect().height + marginTop + marginBottom;
            }

            if (items.length > VISIBLE_COUNT) {
                certScroll.style.maxHeight = `${Math.ceil(totalHeight)}px`;
            } else {
                certScroll.style.maxHeight = 'none';
            }
        };

        requestAnimationFrame(sizeCertScroll);
        window.addEventListener('load', sizeCertScroll);
        window.addEventListener('resize', sizeCertScroll);

        const badgeImages = certScroll.querySelectorAll('img');
        badgeImages.forEach(img => {
            if (!img.complete) {
                img.addEventListener('load', sizeCertScroll, { once: true });
            }
        });
    }
});
