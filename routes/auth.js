// Copyright © 2026 Sthenos Security. All rights reserved.
/**
 * Express Router — Auth Routes (Middleware Chain Pattern)
 *
 * Tests route detection when middleware is chained before the handler.
 * Express allows: router.get('/path', middleware1, middleware2, handler)
 *
 * EXPECTED ROUTE DETECTIONS:
 *   ROUTE-A1: router.get('/me', authMiddleware, ...) — middleware + inline
 *   ROUTE-A2: router.post('/register', validateBody, ...) — middleware + inline
 *   ROUTE-A3: router.post('/logout', authMiddleware, ...) — middleware + inline
 *   ROUTE-A4: router.post('/reset-password', rateLimiter, ...) — double middleware + inline
 *
 * EXPECTED CWE:
 *   CWE-943: NoSQL injection in /register (unsanitized email in query)
 *
 * EXPECTED SECRET:
 *   SEC-A1: Hardcoded session secret
 */

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const router = express.Router();

// SEC-A1: Hardcoded session secret (REACHABLE — used in /me)
const SESSION_SECRET = 'my_session_secret_never_share_2024';

// Middleware — should NOT be detected as route handlers
function authMiddleware(req, res, next) {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, SESSION_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function validateBody(req, res, next) {
    if (!req.body.email) return res.status(400).json({ error: 'Email required' });
    next();
}

function rateLimiter(req, res, next) {
    // Simplified rate limiter
    next();
}

// ROUTE-A1: Middleware chain + inline handler
router.get('/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

// ROUTE-A2: Middleware + inline handler
// CWE-943: NoSQL injection — email from body goes straight to findOne
router.post('/register', validateBody, async (req, res) => {
    const existing = await mongoose.connection.collection('users').findOne({
        email: req.body.email
    });
    if (existing) return res.status(409).json({ error: 'Exists' });
    await mongoose.connection.collection('users').insertOne(req.body);
    res.json({ status: 'registered' });
});

// ROUTE-A3: Middleware + inline
router.post('/logout', authMiddleware, (req, res) => {
    // In real app, invalidate token
    res.json({ status: 'logged out' });
});

// ROUTE-A4: Double middleware + inline handler
router.post('/reset-password', rateLimiter, validateBody, async (req, res) => {
    await mongoose.connection.collection('users').updateOne(
        { email: req.body.email },
        { $set: { resetToken: Math.random().toString(36) } }
    );
    res.json({ status: 'reset email sent' });
});


// ============================================================
// DEAD CODE
// ============================================================
function legacyAuth(token) {
    return jwt.verify(token, 'old_session_key_2020');
}

module.exports = router;
