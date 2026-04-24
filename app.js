// Copyright © 2026 Sthenos Security. All rights reserved.
/**
 * Intentionally Vulnerable Express Application
 * For testing REACHABLE security scanning
 *
 * EXPECTED FINDINGS:
 * ==================
 * CVEs:      4 (via package.json - lodash, axios, mongoose, express)
 * Secrets:   3 (JWT secret, API key, DB connection string — HARDCODED = flagged)
 * CWEs:      3 (NoSQL injection, XSS, prototype pollution)
 * Config:    4 (via Dockerfile)
 * Malware:   0 (process.env reads are secure loading, NOT credential harvesting)
 *
 * SECURE LOADING (should NOT be flagged):
 * - SAFE-001: process.env.STRIPE_SECRET_KEY (env var = secure)
 * - SAFE-002: process.env.REDIS_URL (env var with fallback = secure)
 * - SAFE-003: getVaultSecret() pattern (vault/SSM = secure)
 *
 * REACHABILITY:
 * - 9 findings should be REACHABLE
 * - 1 finding should be UNREACHABLE (dead code)
 */

const express = require('express');
const mongoose = require('mongoose');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// ============================================================
// SECRET FINDINGS (3 total)
// ============================================================

// SECRET-001: JWT Secret (REACHABLE - used in /login)
const JWT_SECRET = 'super_secret_jwt_key_12345_do_not_share';

// SECRET-002: Third-party API Key (REACHABLE - used in /weather)
const WEATHER_API_KEY = 'wk_live_abc123def456ghi789jkl012mno345';

// SECRET-003: MongoDB Connection String (UNREACHABLE - connectLegacy never called)
const LEGACY_MONGO_URI = 'mongodb://admin:MongoPass123!@legacy-db.example.com:27017/legacydb';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://user:Password123@db.example.com:27017/app';


// ============================================================
// CWE FINDINGS (3 total)
// ============================================================

// CWE-943: NoSQL Injection (REACHABLE - /user endpoint)
app.get('/user', async (req, res) => {
    const { username } = req.query;
    const user = await mongoose.connection.collection('users').findOne({
        username: username
    });
    res.json(user || { error: 'Not found' });
});


// CWE-79: Reflected XSS (REACHABLE - /search endpoint)
app.get('/search', (req, res) => {
    const query = req.query.q || '';
    res.send(`
        <html><head><title>Search Results</title></head>
        <body><h1>Results for: ${query}</h1><p>No results found.</p></body>
        </html>
    `);
});


// CWE-1321: Prototype Pollution (REACHABLE - /merge endpoint)
app.post('/merge', (req, res) => {
    const userConfig = req.body.config || {};
    const defaultConfig = { theme: 'light', lang: 'en' };
    const merged = _.merge({}, defaultConfig, userConfig);
    res.json({ config: merged });
});


// ============================================================
// REACHABLE CODE PATHS
// ============================================================

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        const token = jwt.sign(
            { username, role: 'user' },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        return res.json({ token });
    }
    res.status(401).json({ error: 'Invalid credentials' });
});


app.get('/weather/:city', async (req, res) => {
    const { city } = req.params;
    try {
        const response = await axios.get(
            'https://api.weather.example.com/v1/current',
            { params: { city }, headers: { 'X-API-Key': WEATHER_API_KEY } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Weather service unavailable' });
    }
});


async function connectDB() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('MongoDB connection error:', err);
    }
}


// ============================================================
// SECURE SECRET LOADING (should NOT be flagged)
// ============================================================

// SAFE-001: Secret loaded from environment variable (secure method)
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;

// SAFE-002: Secret loaded from environment with fallback
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// SAFE-003: Secret loaded via SDK (simulated vault/SSM fetch)
// In real code: const secret = await SecretClient.getSecret("my-api-key");
async function getVaultSecret(name) {
    // This pattern represents fetching from AWS SSM, HashiCorp Vault,
    // Azure Key Vault, etc. The secret is never in source code.
    return process.env[name];
}

app.get('/payment', async (req, res) => {
    if (!STRIPE_KEY) return res.status(500).json({ error: 'Stripe not configured' });
    res.json({ status: 'Stripe configured via env var' });
});


// ============================================================
// UNREACHABLE CODE (dead code)
// ============================================================

async function connectLegacy() {
    return mongoose.createConnection(LEGACY_MONGO_URI);
}

function deprecatedAuth(token) {
    return jwt.verify(token, 'old_secret_key_deprecated');
}

function _hiddenCallback() {
    const encoded = Buffer.from('console.log("test")').toString('base64');
    eval(Buffer.from(encoded, 'base64').toString());
}


// ============================================================
// STARTUP
// ============================================================

app.get('/', (req, res) => {
    res.json({
        name: 'REACHABLE Test App - Node.js',
        status: 'Intentionally Vulnerable',
        endpoints: ['/user', '/search', '/merge', '/login', '/weather/:city']
    });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;

connectDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
    });
});

module.exports = app;
