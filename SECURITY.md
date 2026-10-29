# Security Policy

## Supported versions

This project is a static single-page site. Only the latest version on the `main` branch, as deployed to GitHub Pages, is supported. Fixes are not backported.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older commits / forks | ❌ |

## Reporting a vulnerability

**Please do not report security issues through public GitHub issues, discussions or pull requests.**

Report them privately using GitHub's **[Report a vulnerability](https://github.com/Abhi1690/epss-checker/security/advisories/new)** form, under the repository's **Security** tab.

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept (input values, files, browser and version)
- The affected file(s) and line(s), if known
- Any suggested fix

## What to expect

| Step | Target time |
|---|---|
| Acknowledgement of your report | Within 3 business days |
| Initial assessment | Within 7 days |
| Fix or mitigation for confirmed issues | Within 30 days, depending on severity |

You'll be kept updated on progress. With your permission, you'll be credited in the security advisory once a fix is released.

## Scope

**In scope**

- Cross-site scripting (XSS) or HTML injection
- Content-Security-Policy bypasses
- Gaps in input validation for CVE IDs, dates or file uploads
- Unsafe handling of API responses
- Formula or XML injection in the exported `.xlsx` file
- Clickjacking or framing issues
- Anything that causes data to be sent somewhere other than `api.first.org`

**Out of scope**

- The FIRST EPSS API itself, or the accuracy of EPSS scores. Report these to FIRST at <epss-chairs@first.org>.
- GitHub Pages infrastructure, such as missing HTTP response headers that GitHub Pages can't set. Report platform issues to [GitHub](https://bounty.github.com/).
- Issues that need a compromised browser, malicious browser extensions or physical access to the device
- Denial of service through very large inputs on your own machine
- Reports produced only by automated scanners, without a demonstrated impact

## Safe harbour

Good-faith research that follows this policy is welcome. We won't pursue action against researchers who avoid privacy violations and service disruption, test only against their own browser or a local copy, and give reasonable time for a fix before disclosure.

Please don't send automated or high-volume traffic to `api.first.org` while testing.
