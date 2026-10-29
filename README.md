# EPSS Score Checker

A lightweight, dependency-free single page for looking up [EPSS](https://www.first.org/epss/) scores via the public [FIRST.org EPSS API](https://www.first.org/epss/api).

- **Single lookup** – one CVE, optional historical date.
- **Bulk lookup** – up to 2,000 CVEs (paste or load `.txt`/`.csv`), batched 100 per request, sortable table, download as native `.xlsx`.

Live: https://abhi1690.github.io/epss-checker/

## Security
- Strict Content-Security-Policy: scripts/styles only from this origin, network only to `https://api.first.org`, no inline script, no `eval`, `form-action 'none'`, `base-uri 'none'`.
- Input validation: CVE IDs must match `^CVE-\d{4}-\d{4,7}$` (year 1999–next year), deduplicated, length-capped; dates must be valid `YYYY-MM-DD` between 2021-04-14 and today; uploads limited to 1 MB `.txt`/`.csv`, only CVE tokens extracted.
- API responses are validated (envelope, CVE format, only requested CVEs, scores numeric in [0,1]); anything else is dropped.
- All output rendered via `textContent` (no `innerHTML`); requests use `credentials: 'omit'`, `no-referrer`, `redirect: 'error'`, timeouts and backoff on 429/5xx.
- Excel is generated in-browser with inline strings only (no formulas → no formula injection). No third-party libraries, no cookies, no storage, no analytics.
- Frame-busting check (GitHub Pages cannot send `X-Frame-Options`/`frame-ancestors`).

EPSS data © FIRST.org.
