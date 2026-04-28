// Copyright © 2026 Sthenos Security. All rights reserved.
/**
 * Express Router — Admin Routes (Mixed Handler Patterns)
 *
 * Tests various Express route registration patterns:
 *   - app.route('/path').get(handler).post(handler)  (chained methods)
 *   - Named function expressions (const handler = function(req, res) {...})
 *   - Async named handlers
 *   - Route with regex parameter constraints
 *
 * EXPECTED ROUTE DETECTIONS:
 *   ROUTE-AD1: router.get('/dashboard', ...) — inline
 *   ROUTE-AD2: router.get('/users', ...) — named function expression
 *   ROUTE-AD3: router.post('/users/:id/ban', ...) — async named
 *   ROUTE-AD4: router.delete('/users/:id', ...) — inline
 *   ROUTE-AD5: router.get('/logs', ...) — inline
 *   ROUTE-AD6: router.patch('/settings', ...) — inline
 *
 * EXPECTED CWE:
 *   CWE-79: XSS in /dashboard (unsanitized query in HTML response)
 *   CWE-943: NoSQL injection in /users (unsanitized role filter)
 */

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();


// ROUTE-AD1: Inline — CWE-79 XSS (query reflected in HTML)
router.get('/dashboard', (req, res) => {
    const filter = req.query.filter || 'all';
    res.send(`
        <html><head><title>Admin Dashboard</title></head>
        <body><h1>Dashboard — Filter: ${filter}</h1></body>
        </html>
    `);
});


// ROUTE-AD2: Named function expression handler
// CWE-943: NoSQL injection — role from query goes to find()
const listUsers = async function(req, res) {
    const role = req.query.role;
    const users = await mongoose.connection.collection('users').find({
        role: role
    }).toArray();
    res.json(users);
};
router.get('/users', listUsers);


// ROUTE-AD3: Async named function declaration
async function banUser(req, res) {
    await mongoose.connection.collection('users').updateOne(
        { _id: req.params.id },
        { $set: { banned: true, bannedAt: new Date() } }
    );
    res.json({ status: 'banned' });
}
router.post('/users/:id/ban', banUser);


// ROUTE-AD4: Inline arrow with destructuring
router.delete('/users/:id', async (req, res) => {
    const { id } = req.params;
    await mongoose.connection.collection('users').deleteOne({ _id: id });
    res.json({ status: 'deleted' });
});


// ROUTE-AD5: Inline — reads logs (potential path traversal in real app)
router.get('/logs', async (req, res) => {
    const level = req.query.level || 'error';
    const logs = await mongoose.connection.collection('logs').find({
        level: level
    }).sort({ timestamp: -1 }).limit(100).toArray();
    res.json(logs);
});


// ROUTE-AD6: PATCH — partial update
router.patch('/settings', async (req, res) => {
    const settings = req.body;
    await mongoose.connection.collection('settings').updateOne(
        { key: 'global' },
        { $set: settings },
        { upsert: true }
    );
    res.json({ status: 'updated' });
});


// ============================================================
// DEAD CODE — should NOT be reachable
// ============================================================

// Exported but never mounted on any router/app
async function purgeDatabase(req, res) {
    await mongoose.connection.dropDatabase();
    res.json({ status: 'purged' });
}

// Internal helper never called from any route
function formatAuditLog(action, userId) {
    return { action, userId, timestamp: new Date().toISOString() };
}

module.exports = router;
