# reach-testbed-github

Intentionally vulnerable Node.js/Express app for testing [REACHABLE](https://sthenosec.com) on GitHub Actions.

> **Do not deploy this application.** It contains intentional security vulnerabilities for testing purposes.

---

## Quick Start

1. **Fork** this repo
2. **Push** — pipeline runs automatically on push to `main` and on PRs
3. Check the **Actions** tab for scan results
4. Check the **Security** tab for SARIF findings

### Enable AI Reachability (Optional)

AI reachability adds variable-level taint analysis on top of the call graph — it determines whether the variable flowing into a vulnerable sink is actually attacker-controlled.

1. Get a free API key at [console.groq.com/keys](https://console.groq.com/keys)
2. Add `GROQ_API_KEY` as a repository secret (Settings → Secrets and variables → Actions → New repository secret)
3. Push — AI analysis runs automatically

No key? The scan still works. AI just adds deeper analysis.

---

## Expected Findings

| Signal | Count | Reachable | Not Reachable |
|--------|------:|----------:|--------------:|
| CVE | 4 | 3 | 1 |
| SECRET | 3 | 2 | 1 |
| CWE | 3 | 3 | 0 |
| CONFIG | 4 | — | — |
| **Total** | **14** | **8** | **2** |

> Noise reduction: 8 reachable out of 14 total = **43% noise reduction**

### CVEs (via package.json)

| Package | CVE | Severity | Reachable? |
|---------|-----|----------|-----------|
| lodash 4.17.20 | CVE-2021-23337 | HIGH | ✅ Used in `/merge` |
| axios 0.21.0 | CVE-2021-3749 | HIGH | ✅ Used in `/weather` |
| mongoose 5.10.0 | CVE-2023-3696 | MEDIUM | ✅ Used in `/user` |
| express 4.17.1 | CVE-2022-24999 | MEDIUM | ❌ qs parser not triggered |

### CWEs (in app.js)

| CWE | Description | Endpoint | Reachable? |
|-----|-------------|----------|-----------|
| CWE-943 | NoSQL Injection | `/user` | ✅ |
| CWE-79 | Reflected XSS | `/search` | ✅ |
| CWE-1321 | Prototype Pollution | `/merge` | ✅ |

### Secrets (in app.js)

| Secret | Location | Reachable? |
|--------|----------|-----------|
| JWT Secret | `JWT_SECRET` → `/login` | ✅ |
| API Key | `WEATHER_API_KEY` → `/weather` | ✅ |
| MongoDB URI | `LEGACY_MONGO_URI` → `connectLegacy()` | ❌ Dead code |

### Config (Dockerfile)

| Issue | Line | Severity |
|-------|------|----------|
| Unpinned `node:latest` | FROM | MEDIUM |
| npm as root | RUN | HIGH |
| Debug port exposed | EXPOSE 9229 | MEDIUM |
| Running as root | No USER | HIGH |

---

## AI Reachability

With `GROQ_API_KEY` set, the scan adds a second analysis layer:

```
Step 1 (call graph):  Is the FUNCTION reachable?     → 8 yes, 2 no
Step 2 (AI taint):    Is the VARIABLE exploitable?    → confirms/downgrades
```

The AI reads the actual code and determines whether `req.query.username` flowing into `findOne()` is attacker-controlled (yes → confirmed) or whether `LEGACY_MONGO_URI` used in dead code is exploitable (no → safe).

---

## Pipeline Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REACHABLE_DIST_REPO` | `sthenos-security/reach-dist` | Distribution repo |
| `REACHABLE_VERSION` | _(latest)_ | Pin a specific version |
| `FAIL_THRESHOLD` | `high` | `critical\|high\|medium\|any\|none` |
| `RUNNER_LABEL` | `ubuntu-latest` | Self-hosted runner label |
| `GROQ_API_KEY` | _(secret)_ | AI reachability API key (optional) |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

© 2026 Sthenos Security. All rights reserved. REACHABLE is a trademark of Sthenos Security. Patent Pending.
