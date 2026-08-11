# CyberLab — Flask Web Security Lab

A small banking-style Flask application with **real, working backend logic**
(accounts, balances, transfers, bcrypt auth, CSRF, rate limiting), plus an
optional set of deliberately vulnerable OWASP-style training endpoints kept
completely separate from the production app.

Two things ship in one repo:

1. **The hardened app** — registered by default. Safe to deploy.
2. **The lab** — a Flask blueprint under `/lab`, mounted only when
   `CYBERLAB_LAB_MODE=1`. Never enable this on a host anyone else can reach.

---

## Quick start (production-safe mode)

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt

python -c "import secrets; print(secrets.token_hex(32))"   # generate a key
set CYBERLAB_SECRET_KEY=<paste the key>                    # Windows cmd
# $env:CYBERLAB_SECRET_KEY = "<paste the key>"              # PowerShell
# export CYBERLAB_SECRET_KEY=<paste the key>                # bash

python app.py
```

Open `http://127.0.0.1:5000`. Register an account, sign in, save a bio,
transfer funds to another account, and (if you set `CYBERLAB_ADMIN_USERS`)
view the admin panel.

Outside lab mode, `app.py` **refuses to start** without
`CYBERLAB_SECRET_KEY` — a missing key would mean sessions can't survive a
process restart or a multi-worker deployment, and a hardcoded fallback would
let anyone forge a session cookie.

---

## Configuration (environment variables)

All of these have safe defaults for a hardened deployment; only
`CYBERLAB_SECRET_KEY` is mandatory.

| Variable | Default | Purpose |
|---|---|---|
| `CYBERLAB_SECRET_KEY` | *(required outside lab mode)* | Flask session signing key, ≥32 chars |
| `CYBERLAB_LAB_MODE` | `0` | `1` mounts the vulnerable `/lab/*` endpoints |
| `CYBERLAB_DATABASE` | `database/auth.db` | SQLite file path |
| `CYBERLAB_FORCE_HTTPS` | `1` (`0` in lab mode) | Sets the `Secure` cookie flag + HSTS |
| `CYBERLAB_TRUSTED_PROXIES` | `0` | Number of reverse proxies in front of the app; only then is `X-Forwarded-For` trusted for rate limiting |
| `CYBERLAB_ADMIN_USERS` | *(empty)* | Comma-separated usernames granted the admin role at startup |
| `CYBERLAB_MAX_ATTEMPTS` | `5` | Failed logins before an account locks |
| `CYBERLAB_LOCK_SECONDS` | `300` | Lockout duration |
| `CYBERLAB_LOGIN_RATE_MAX` / `CYBERLAB_LOGIN_RATE_WINDOW` | `10` / `60` | Per-IP throttle on `/login` and `/register` |
| `CYBERLAB_MIN_PASSWORD_LEN` | `12` | Minimum password length (max is a hard 72 bytes — bcrypt's limit) |
| `CYBERLAB_STARTING_BALANCE_CENTS` | `100000` | Starting balance for new accounts ($1,000.00) |
| `CYBERLAB_HOST` / `CYBERLAB_PORT` | `127.0.0.1` / `5000` | Only used by `python app.py` directly |
| `CYBERLAB_DEBUG` | `0` | Never enable on a reachable host — the Werkzeug debugger is remote code execution |

---

## Deploying

`python app.py` uses Flask's development server — fine for local testing,
**not** for the open internet (no concurrency, no crash recovery). A
`Procfile` is included for platforms that read one (Railway, Heroku-style
hosts):

```
web: waitress-serve --host=0.0.0.0 --port=$PORT app:app
```

`waitress` is in `requirements.txt`. It's pure Python, so the same command
works locally on Windows and on the Linux container most PaaS hosts run.

**Render** doesn't auto-read a `Procfile` — paste the same command as the
service's Start Command in its dashboard, with Build Command
`pip install -r requirements.txt`.

### Environment variables to set on the host

| Variable | Value |
|---|---|
| `CYBERLAB_SECRET_KEY` | A fresh secret — generate one locally, **never reuse one that appeared in a chat, terminal history, or commit.** |
| `CYBERLAB_LAB_MODE` | Leave unset (or `0`). If this is ever `1` on a public host, the SQLi/XSS training pages are live for anyone. |
| `CYBERLAB_TRUSTED_PROXIES` | `1` — every mainstream PaaS puts a proxy in front of your app; without this the per-IP login throttle sees the proxy's IP instead of the real client's. |
| `CYBERLAB_ADMIN_USERS` | Your own username, if you want an admin account. |

### The database will not survive a redeploy on most PaaS free tiers

`database/auth.db` is a plain file on local disk. Render, Railway, and
similar platforms typically reset local disk on every deploy and often on
every restart, unless you attach a persistent volume/disk (usually a paid
add-on). Until you do that, expect every registered account to vanish the
next time the service redeploys. For a portfolio/demo this may be
acceptable; for anything real, attach a persistent volume and point
`CYBERLAB_DATABASE` at a path inside it, or migrate to a hosted database.

---

## Running the tests

```bash
python test_app.py                       # app: auth, CSRF, transfers, XSS/SQLi
python -m security_scanner.test_scanner  # scanner package
```

Both are plain `assert`-based scripts (no test framework required) and print
a pass/fail line per check plus a summary.

---

## What's actually implemented

* **Accounts** — bcrypt-hashed passwords, per-account lockout after repeated
  failures with automatic expiry, generic error messages so login responses
  can't be used to enumerate valid usernames, constant-time-ish comparison
  even for unknown usernames.
* **CSRF** — every state-changing request is checked against a per-session
  token in one `before_request` hook, not per-handler.
* **Transfers** — real money movement between two accounts, stored in cents
  (not floats), atomic (a failed debit never leaves a floating credit), and
  rejects overdrafts, unknown recipients, and self-transfers.
* **Authorization** — `/admin` checks both *are you signed in* (401 →
  redirect to login) and *do you hold the admin role* (403) as two distinct
  checks, matching how the broken-access-control lab demonstrates skipping
  the second one.
* **Security headers** — CSP with no `unsafe-inline` (all styling moved to
  `static/style.css`, all templates render through Jinja instead of f-strings
  so there's nothing for an inline-script CSP exception to protect), HSTS,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `Permissions-Policy`.
* **Rate limiting** — a sliding-window per-IP throttle on `/login` and
  `/register`, independent of the account lockout (which is per-username).

## The lab (`CYBERLAB_LAB_MODE=1`)

Each vulnerable endpoint sits next to its hardened counterpart so you can
compare the same feature broken vs. fixed:

| Vulnerability | Vulnerable | Hardened |
|---|---|---|
| SQL injection | `/lab/login-sqli` | `/login` |
| Stored XSS | `/lab/profile-xss` | `/profile` |
| Reflected XSS | `/lab/search-xss` | `/search` |
| Broken access control | `/lab/admin-open` | `/admin` |
| Cookie exfiltration sink | `/lab/steal` | — (demonstrates `HttpOnly`) |

`attacker.html` is a minimal auto-submitting CSRF proof-of-concept aimed at
`/transfer`; with the app's CSRF token check it gets rejected (open the file
directly in a browser while signed in to see the 400).

---

## `security_scanner/` — a small authorized-testing scanner

A separate, general-purpose tool (not tied to this lab app) that sends
benign detection probes — never exploit payloads — at a URL you explicitly
authorize, and reports what it observed.

```bash
python -m security_scanner https://example.com \
    --authorize --confirm I_AUTHORIZE_TESTING
```

* Refuses to run without `--authorize --confirm I_AUTHORIZE_TESTING`.
* Refuses targets that resolve to loopback/private/link-local addresses
  unless you pass `--allow-internal` (stops the scanner being pointed at
  internal infrastructure via a malicious hostname — an SSRF guard).
* Caps total requests per scan and bytes read per response, rate-limits
  itself between requests, and verifies TLS certificates.
* Checks: SQL error-message leakage, reflected-XSS probing, path-traversal
  indicators, missing security headers, weak cookie flags, and a few common
  sensitive-path probes (all GET, all read-only).
* `--json` for machine-readable output, `-o file` to write the report,
  `--min-interval` to slow it down further.

It is heuristic — a probe's presence/absence in a response is evidence, not
proof. It only guesses a form's parameter name from the query string you
already gave it, so pass the real `?param=value` for accurate results
against endpoints that don't use `q`.

---

## Before you make this repository public

`database/auth.db` (a working copy with bcrypt-hashed test accounts) was
previously committed to git. It's now covered by `.gitignore` and removed
from tracking going forward, but **it still exists in earlier commits** in
this repo's history. If this repo is going to be pushed to a public host,
either start a fresh repo without that history, or rewrite history (e.g.
`git filter-repo`) before pushing — `git rm --cached` alone does not remove
it from past commits.

---

## Threat model (unchanged from the original)

* Attackers can supply arbitrary input to any endpoint.
* Victims may be authenticated.
* Browsers enforce modern cookie/CSP rules — the app relies on that, so test
  in a real browser, not just `curl`.
* The goal is defense in depth: no single control is assumed sufficient.
