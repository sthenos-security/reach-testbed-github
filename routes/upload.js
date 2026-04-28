// Copyright © 2026 Sthenos Security. All rights reserved.
/**
 * Express Router — File Upload Routes (Error Handling Patterns)
 *
 * Tests route detection with try/catch blocks, multiple response paths,
 * and callback-style handlers.
 *
 * EXPECTED ROUTE DETECTIONS:
 *   ROUTE-U1: router.post('/upload', ...) — inline with try/catch
 *   ROUTE-U2: router.get('/files', ...) — inline
 *   ROUTE-U3: router.get('/files/:name', ...) — inline with path traversal vuln
 *   ROUTE-U4: router.delete('/files/:name', ...) — inline
 *
 * EXPECTED CWE:
 *   CWE-22: Path traversal in /files/:name (unsanitized filename)
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

const UPLOAD_DIR = '/tmp/uploads';

// ROUTE-U1: Inline with try/catch
router.post('/upload', async (req, res) => {
    try {
        const { filename, content } = req.body;
        const filePath = path.join(UPLOAD_DIR, filename);
        fs.writeFileSync(filePath, content);
        res.json({ status: 'uploaded', path: filePath });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ROUTE-U2: Simple listing
router.get('/files', (req, res) => {
    try {
        const files = fs.readdirSync(UPLOAD_DIR);
        res.json({ files });
    } catch (err) {
        res.json({ files: [] });
    }
});

// ROUTE-U3: CWE-22 Path Traversal — filename not sanitized
router.get('/files/:name', (req, res) => {
    const filePath = path.join(UPLOAD_DIR, req.params.name);
    // BUG: req.params.name could be ../../etc/passwd
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        res.send(content);
    } catch (err) {
        res.status(404).json({ error: 'File not found' });
    }
});

// ROUTE-U4: Delete file
router.delete('/files/:name', (req, res) => {
    const filePath = path.join(UPLOAD_DIR, req.params.name);
    try {
        fs.unlinkSync(filePath);
        res.json({ status: 'deleted' });
    } catch (err) {
        res.status(404).json({ error: 'File not found' });
    }
});


// ============================================================
// DEAD CODE
// ============================================================
function cleanupOldFiles() {
    // Scheduled task — never called from any route
    const files = fs.readdirSync(UPLOAD_DIR);
    files.forEach(f => {
        const stat = fs.statSync(path.join(UPLOAD_DIR, f));
        if (Date.now() - stat.mtimeMs > 86400000) {
            fs.unlinkSync(path.join(UPLOAD_DIR, f));
        }
    });
}

module.exports = router;
