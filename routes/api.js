// Copyright © 2026 Sthenos Security. All rights reserved.
/**
 * Express Router — Route Detection Test Cases
 *
 * Tests that REACHABLE detects routes registered via express.Router()
 * in addition to direct app.get()/app.post() on the main app object.
 *
 * EXPECTED ROUTE DETECTIONS:
 *   ROUTE-R1: router.get('/profile/:id', ...) — inline arrow handler
 *   ROUTE-R2: router.post('/profile', ...)    — inline arrow handler
 *   ROUTE-R3: router.delete('/profile/:id', ...) — named handler reference
 *   ROUTE-R4: router.put('/profile/:id', ...) — named handler reference
 *
 * EXPECTED CWE:
 *   CWE-943: NoSQL injection in getProfile (unsanitized req.params.id)
 *
 * EXPECTED SECRET:
 *   None (secrets are in app.js)
 */

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

// ROUTE-R1: Inline arrow handler (same pattern as app.js routes)
// CWE-943: NoSQL injection — unsanitized id goes straight to findOne
router.get('/profile/:id', async (req, res) => {
    const profile = await mongoose.connection.collection('profiles').findOne({
        _id: req.params.id
    });
    res.json(profile || { error: 'Not found' });
});

// ROUTE-R2: Inline arrow handler with body parsing
router.post('/profile', async (req, res) => {
    const { name, email } = req.body;
    await mongoose.connection.collection('profiles').insertOne({ name, email });
    res.json({ status: 'created' });
});

// ROUTE-R3: Named handler reference — deleteProfile is defined separately
async function deleteProfile(req, res) {
    await mongoose.connection.collection('profiles').deleteOne({
        _id: req.params.id
    });
    res.json({ status: 'deleted' });
}
router.delete('/profile/:id', deleteProfile);

// ROUTE-R4: Named handler reference — updateProfile
async function updateProfile(req, res) {
    await mongoose.connection.collection('profiles').updateOne(
        { _id: req.params.id },
        { $set: req.body }
    );
    res.json({ status: 'updated' });
}
router.put('/profile/:id', updateProfile);


// ============================================================
// DEAD CODE — should NOT be reachable
// ============================================================

// This handler is defined but never registered on any route
async function orphanedHandler(req, res) {
    const data = await mongoose.connection.collection('admin').find({}).toArray();
    res.json(data);
}

module.exports = router;
