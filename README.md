<div align="center">

# EPSS Score Checker

**Look up how likely a CVE is to be exploited, for one CVE or many, right in your browser.**

[![Live demo](https://img.shields.io/badge/demo-GitHub%20Pages-0969da?logo=github)](https://abhi1690.github.io/epss-checker/)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![No build step](https://img.shields.io/badge/build-none-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Live demo](https://abhi1690.github.io/epss-checker/) · [Report a bug](https://github.com/Abhi1690/epss-checker/issues) · [Security policy](SECURITY.md)

</div>

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Understanding the scores](#understanding-the-scores)
- [Data source and attribution](#data-source-and-attribution)
- [Security model](#security-model)
- [Privacy](#privacy)
- [Limitations](#limitations)
- [Project structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Overview

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/) estimates how likely it is that a published CVE will be exploited in the wild in the next 30 days. The EPSS Special Interest Group at [FIRST](https://www.first.org/) maintains it.

EPSS Score Checker is a single static web page that queries the public [FIRST EPSS API](https://api.first.org/epss). It has no backend, no build step and no third-party JavaScript. You can host it on GitHub Pages or any static file host, or open it locally.

## Features

| Feature | Description |
|---|---|
| 🔎 **Single lookup** | Get one CVE's score, percentile and score date, with an optional historical date. |
| 📋 **Bulk lookup** | Paste up to 2,000 CVE IDs or load a `.txt` / `.csv` file. Duplicates are removed and lookups are sent in batches of 100. |
| ↕️ **Sortable results** | Sort by CVE, EPSS, percentile, date or status. Each CVE links to its NVD record. |
| 📊 **Excel export** | Download a native `.xlsx` with a frozen header, filters, number formats and an *Info* sheet that records the request. |
| 🛡️ **Hardened by default** | Strict Content-Security-Policy, input validation, checks on API responses and output inserted as plain text only. |
| 🪶 **Lightweight** | Three files (HTML, CSS, JS) totalling about 30 KB, with dark-mode support. |

## Quick start

### Use it online

<https://abhi1690.github.io/epss-checker/>

### Run locally

```bash
git clone https://github.com/Abhi1690/epss-checker.git
cd epss-checker
python3 -m http.server 8000
# open http://localhost:8000
```

> [!NOTE]
> Serve the page over HTTP rather than opening `index.html` as a `file://` URL. Browsers apply CSP and CORS rules differently for local files.

### Deploy your own copy

1. Fork this repository.
2. Go to **Settings → Pages → Build and deployment**, choose **Deploy from a branch**, then `main` and `/ (root)`.
3. Optional: add a custom domain and turn on **Enforce HTTPS**.

## Usage

### Single lookup

1. Enter a CVE ID, for example `CVE-2024-3400`. Upper or lower case is fine, and spaces are trimmed.
2. Optionally pick a **score date** to see the score as it was on that day.
3. Select **Check**.

### Bulk lookup

1. Paste CVE IDs separated by commas, spaces, semicolons or new lines, or load a `.txt` / `.csv` file (max 1 MB). When you load a file, only text matching the CVE format is kept.
2. Optionally pick a **score date**.
3. Select **Check all**, then **Download Excel (.xlsx)**.

The run is rejected if any entry is invalid, and the invalid entries are listed so you can fix them.

### Equivalent API call

```bash
curl "https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2023-4966&date=2026-10-27"
```

## Understanding the scores

| Field | Meaning |
|---|---|
| `epss` | Probability (0–1) of exploitation activity in the next 30 days. |
| `percentile` | Share of all scored CVEs with an equal or lower EPSS score. |
| `date` | Date the score was published. |

EPSS complements CVSS: CVSS measures how severe a vulnerability is, and EPSS estimates how likely it is to be exploited. FIRST recommends using EPSS together with other context, such as the CISA KEV catalogue, asset criticality and exposure, rather than on its own.

> [!IMPORTANT]
> **The model changes over time.** Each new EPSS model version shifts scores on the day it starts publishing. Don't compare scores from before and after these dates as if they used the same scale.

| Model | Publishing since |
|---|---|
| EPSS v1 | 2021-04-14 |
| EPSS v2 (v2022.01.01) | 2022-02-04 |
| EPSS v3 (v2023.03.01) | 2023-03-07 |
| EPSS v4 (v2025.03.14) | 2025-03-17 |
| EPSS v5 (v2026.06.15) | 2026-06-15 |

## Data source and attribution

All scores come live from the FIRST EPSS API (`https://api.first.org/data/v1/epss`). This project does not store, cache or redistribute EPSS data.

- **Free to use, no registration required.** FIRST publishes EPSS free of charge and asks for attribution when it is used in publications or products. FIRST does not name a specific licence.
- **API is for lookups, not bulk.** FIRST describes the API as intended for one CVE or a small batch. For large-scale or recurring jobs, such as syncing every score or joining against an asset inventory, use the official bulk sources instead:
  - Daily CSV: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  - Historical archive (back to 2021-04-14): [`empiricalsec/epss_scores`](https://github.com/empiricalsec/epss_scores)
- **Maintainers.** The EPSS SIG at FIRST maintains EPSS. The data, data science and scoring infrastructure are provided by [Empirical Security](https://www.empiricalsecurity.com/).

### Suggested citation

> EPSS scores courtesy of FIRST.org — <https://www.first.org/epss/>. Score date: `YYYY-MM-DD`, model: `v2026.06.15`.

This project is independent and not affiliated with or endorsed by FIRST or Empirical Security.

## Security model

The page treats all input as untrusted: what you type, files you load, and responses from the API.

| Area | Control |
|---|---|
| **CVE input** | Must match `^CVE-\d{4}-\d{4,7}$` after trimming and upper-casing. Year must be between 1999 and next year. Length is capped at 20 characters per ID and 40,000 per textarea. IDs are de-duplicated, with at most 2,000 per run. |
| **Date input** | Must be a real calendar date in `YYYY-MM-DD` form, between 2021-04-14 and today. |
| **File upload** | Only `.txt` / `.csv` files up to 1 MB are accepted. They are read locally with `FileReader` and only CVE-format text is kept. |
| **API response** | Checks the content type, a 5 MB size cap, a `status: OK` envelope and the shape of each row. Only CVEs you asked for are kept, and scores must be numbers from 0 to 1. Anything else is dropped. |
| **Output (XSS)** | The DOM is built only with `textContent` / `createElement`, never `innerHTML`. Links are created only from validated CVE IDs. |
| **Excel export** | Text cells are written as inline strings and the XML is escaped. No formulas are written, so spreadsheet formula injection isn't possible. |
| **Content-Security-Policy** | `default-src 'none'`. Scripts and styles load only from this site, and network requests go only to `https://api.first.org`. Also sets `form-action 'none'`, `base-uri 'none'`, `object-src 'none'` and `upgrade-insecure-requests`. No inline scripts and no `eval`. |
| **Network requests** | `credentials: 'omit'`, `referrerPolicy: 'no-referrer'`, `redirect: 'error'`, a 20 s timeout and exponential backoff on HTTP 429 / 5xx. |
| **Clickjacking** | The page refuses to show its content inside a frame. GitHub Pages can't send `X-Frame-Options` or `frame-ancestors` headers. |
| **Supply chain** | Zero dependencies, no CDNs, no build tooling. |

> [!CAUTION]
> Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) and report it privately rather than opening a public issue.

## Privacy

- No cookies, `localStorage`, analytics or tracking.
- The only network requests go to `api.first.org`, and they contain only the CVE IDs and date you enter.
- Uploaded files never leave your browser.
- The `.xlsx` file is built in your browser.

## Limitations

- **Availability:** results depend on the FIRST API being up. Batches that fail after retries are marked `Error` instead of failing the whole run.
- **Rate limits:** each request carries 100 CVEs, with a short pause between batches. Respect FIRST's guidance and use the daily CSV for large datasets.
- **Not found:** CVEs that are rejected, reserved, very new or not yet scored return `Not found`.
- **Static hosting:** GitHub Pages can't set custom HTTP security headers, so the CSP is set with a `<meta>` tag. Host it behind a server or CDN that can set headers if you need `frame-ancestors`, HSTS and similar protections.

## Project structure

```text
.
├── index.html   # Markup and Content-Security-Policy
├── app.js       # Validation, API client, rendering, XLSX writer
├── style.css    # Light and dark theme
├── .nojekyll    # Serve files as-is on GitHub Pages
└── README.md
```

## Contributing

Issues and pull requests are welcome. Please:

- Don't add runtime dependencies, CDNs or build steps.
- Don't use `innerHTML`, `eval`, inline scripts or inline event handlers. They would break the CSP.
- Validate every new input on the client side, and treat API data as untrusted.
- Describe how you tested your change, including any edge cases or malicious inputs you tried.

## License

Released under the [MIT License](LICENSE). EPSS data belongs to its publishers and is subject to [FIRST's terms](https://www.first.org/about/policies/terms).

## Disclaimer

This tool is provided "as is", without warranty of any kind. FIRST likewise provides EPSS "as is" and does not guarantee its accuracy, completeness or timeliness. EPSS scores are one input to vulnerability prioritisation, not a verdict on whether a vulnerability is safe to ignore. Always consider your own environment and other threat intelligence.
