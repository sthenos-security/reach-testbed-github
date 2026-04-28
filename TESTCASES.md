# REACHABLE Test Cases — reach-testbed-github

Every row is a regression test. If REACHABLE stops detecting any of these, it's a bug.

Last updated: 2026-04-28

---

## Route Detection (Express)

| ID | File | Pattern | Method | Path | Handler Type | Expected |
|----|------|---------|--------|------|-------------|----------|
| ROUTE-01 | app.js | `app.get(...)` | GET | /user | Inline arrow | ✅ Detected |
| ROUTE-02 | app.js | `app.get(...)` | GET | /search | Inline arrow | ✅ Detected |
| ROUTE-03 | app.js | `app.post(...)` | POST | /merge | Inline arrow | ✅ Detected |
| ROUTE-04 | app.js | `app.post(...)` | POST | /login | Inline arrow | ✅ Detected |
| ROUTE-05 | app.js | `app.get(...)` | GET | /weather/:city | Inline arrow | ✅ Detected |
| ROUTE-06 | app.js | `app.get(...)` | GET | /payment | Inline arrow | ✅ Detected |
| ROUTE-07 | app.js | `app.get(...)` | GET | / | Inline arrow | ✅ Detected |
| ROUTE-08 | app.js | `app.get(...)` | GET | /health | Inline arrow | ✅ Detected |
| ROUTE-R1 | routes/api.js | `router.get(...)` | GET | /profile/:id | Inline arrow | ✅ Detected |
| ROUTE-R2 | routes/api.js | `router.post(...)` | POST | /profile | Inline arrow | ✅ Detected |
| ROUTE-R3 | routes/api.js | `router.delete(...)` | DELETE | /profile/:id | Named handler | ✅ Detected |
| ROUTE-R4 | routes/api.js | `router.put(...)` | PUT | /profile/:id | Named handler | ✅ Detected |
| ROUTE-A1 | routes/auth.js | `router.get(...)` | GET | /me | Middleware + inline | ✅ Detected |
| ROUTE-A2 | routes/auth.js | `router.post(...)` | POST | /register | Middleware + inline | ✅ Detected |
| ROUTE-A3 | routes/auth.js | `router.post(...)` | POST | /logout | Middleware + inline | ✅ Detected |
| ROUTE-A4 | routes/auth.js | `router.post(...)` | POST | /reset-password | Double middleware + inline | ✅ Detected |
| ROUTE-AD1 | routes/admin.js | `router.get(...)` | GET | /dashboard | Inline arrow | ✅ Detected |
| ROUTE-AD2 | routes/admin.js | `router.get(...)` | GET | /users | Named fn expression | ✅ Detected |
| ROUTE-AD3 | routes/admin.js | `router.post(...)` | POST | /users/:id/ban | Named fn declaration | ✅ Detected |
| ROUTE-AD4 | routes/admin.js | `router.delete(...)` | DELETE | /users/:id | Inline arrow | ✅ Detected |
| ROUTE-AD5 | routes/admin.js | `router.get(...)` | GET | /logs | Inline arrow | ✅ Detected |
| ROUTE-AD6 | routes/admin.js | `router.patch(...)` | PATCH | /settings | Inline arrow | ✅ Detected |
| ROUTE-U1 | routes/upload.js | `router.post(...)` | POST | /upload | Inline with try/catch | ✅ Detected |
| ROUTE-U2 | routes/upload.js | `router.get(...)` | GET | /files | Inline arrow | ✅ Detected |
| ROUTE-U3 | routes/upload.js | `router.get(...)` | GET | /files/:name | Inline arrow | ✅ Detected |
| ROUTE-U4 | routes/upload.js | `router.delete(...)` | DELETE | /files/:name | Inline arrow | ✅ Detected |

### Gap fixed (2026-04-28)

**Bug**: `intel_collector.py` Pass F had no `elif lang == "javascript"` block.
`js_intel.py` only resolved named handler references, not inline arrow functions.
Express inline handlers (`app.get('/path', (req, res) => {...})`) silently produced zero routes.

**Result**: Zero entrypoints → everything NOT_REACHABLE → empty SARIF in GitHub Code Scanning.

---

## Entrypoint Classification

| ID | Function | File | Expected | Reason |
|----|----------|------|----------|--------|
| EP-01 | (inline /user) | app.js | ✅ Entrypoint | express_route |
| EP-02 | (inline /search) | app.js | ✅ Entrypoint | express_route |
| EP-03 | (inline /merge) | app.js | ✅ Entrypoint | express_route |
| EP-04 | (inline /login) | app.js | ✅ Entrypoint | express_route |
| EP-05 | (inline /weather) | app.js | ✅ Entrypoint | express_route |
| EP-06 | connectLegacy | app.js | ❌ NOT entrypoint | Dead code |
| EP-07 | deprecatedAuth | app.js | ❌ NOT entrypoint | Dead code |
| EP-08 | _hiddenCallback | app.js | ❌ NOT entrypoint | Dead code |
| EP-09 | orphanedHandler | routes/api.js | ❌ NOT entrypoint | Defined, never registered |
| EP-10 | legacyAuth | routes/auth.js | ❌ NOT entrypoint | Dead code |
| EP-11 | purgeDatabase | routes/admin.js | ❌ NOT entrypoint | Exported, never mounted |
| EP-12 | formatAuditLog | routes/admin.js | ❌ NOT entrypoint | Internal helper, never called |
| EP-13 | cleanupOldFiles | routes/upload.js | ❌ NOT entrypoint | Scheduled task, never called |

---

## CVE Reachability

| ID | Package | CVE | Severity | Reachable? | Why |
|----|---------|-----|----------|-----------|-----|
| CVE-01 | lodash 4.17.20 | CVE-2021-23337 | HIGH | ✅ REACHABLE | `_.merge()` called in /merge handler |
| CVE-02 | axios 0.21.0 | CVE-2021-3749 | HIGH | ✅ REACHABLE | `axios.get()` called in /weather handler |
| CVE-03 | mongoose 5.10.0 | CVE-2023-3696 | MEDIUM | ✅ REACHABLE | `mongoose.connection` used in /user |
| CVE-04 | express 4.17.1 | CVE-2022-24999 | MEDIUM | ❌ NOT_REACHABLE | qs parser not triggered by any route |

---

## CWE Detection

| ID | CWE | Description | File | Line | Reachable? |
|----|-----|-------------|------|------|-----------|
| CWE-01 | CWE-943 | NoSQL Injection | app.js | /user handler | ✅ REACHABLE |
| CWE-02 | CWE-79 | Reflected XSS | app.js | /search handler | ✅ REACHABLE |
| CWE-03 | CWE-1321 | Prototype Pollution | app.js | /merge handler | ✅ REACHABLE |
| CWE-R1 | CWE-943 | NoSQL Injection | routes/api.js | /profile/:id handler | ✅ REACHABLE |
| CWE-A1 | CWE-943 | NoSQL Injection | routes/auth.js | /register handler | ✅ REACHABLE |
| CWE-AD1 | CWE-79 | Reflected XSS | routes/admin.js | /dashboard handler | ✅ REACHABLE |
| CWE-AD2 | CWE-943 | NoSQL Injection | routes/admin.js | /users handler | ✅ REACHABLE |
| CWE-U1 | CWE-22 | Path Traversal | routes/upload.js | /files/:name handler | ✅ REACHABLE |

---

## Secret Detection

| ID | Type | Value Pattern | Reachable? | Why |
|----|------|--------------|-----------|-----|
| SEC-01 | JWT Secret | `super_secret_jwt_key_*` | ✅ REACHABLE | Used in /login `jwt.sign()` |
| SEC-02 | API Key | `wk_live_abc123*` | ✅ REACHABLE | Used in /weather `headers` |
| SEC-03 | MongoDB URI | `mongodb://admin:MongoPass*` | ❌ NOT_REACHABLE | Only in `connectLegacy()` (dead code) |
| SEC-A1 | Session Secret | `my_session_secret_*` | ✅ REACHABLE | Used in authMiddleware → /me, /logout |

### Secure loading (should NOT be flagged as secrets)

| ID | Pattern | Why safe |
|----|---------|---------|
| SAFE-01 | `process.env.STRIPE_SECRET_KEY` | Environment variable |
| SAFE-02 | `process.env.REDIS_URL` | Environment variable with fallback |
| SAFE-03 | `getVaultSecret()` | Vault/SSM fetch pattern |

---

## Dockerfile Config Issues

| ID | Issue | Line | Severity |
|----|-------|------|----------|
| CFG-01 | Unpinned `node:latest` | FROM | MEDIUM |
| CFG-02 | npm as root | RUN | HIGH |
| CFG-03 | Debug port exposed (9229) | EXPOSE | MEDIUM |
| CFG-04 | Running as root (no USER) | CMD | HIGH |

---

## Dead Code / Unreachable

| ID | Function | File | Why unreachable |
|----|----------|------|----------------|
| DEAD-01 | `connectLegacy()` | app.js | Never called |
| DEAD-02 | `deprecatedAuth()` | app.js | Never called |
| DEAD-03 | `_hiddenCallback()` | app.js | Never called |
| DEAD-04 | `orphanedHandler()` | routes/api.js | Defined but never registered on router |
| DEAD-05 | `legacyAuth()` | routes/auth.js | Never called |
| DEAD-06 | `purgeDatabase()` | routes/admin.js | Exported but never mounted |
| DEAD-07 | `formatAuditLog()` | routes/admin.js | Internal helper, never called from route |
| DEAD-08 | `cleanupOldFiles()` | routes/upload.js | Never called |
