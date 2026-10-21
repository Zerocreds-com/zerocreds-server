'use strict';

// Kept in source so both public domains receive the same small, cacheable mark.
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#4f46e5"/><path d="M19 18h26v11H30v6h12v11H30v8H19z" fill="white"/><circle cx="45" cy="40" r="7" fill="#38bdf8"/></svg>`;

function sendFavicon(res) {
  res.writeHead(200, {
    'Content-Type': 'image/svg+xml',
    'Cache-Control': 'public, max-age=86400',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  }).end(FAVICON_SVG);
}

module.exports = { FAVICON_SVG, sendFavicon };
