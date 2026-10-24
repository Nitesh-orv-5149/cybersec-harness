// Deliberately insecure endpoints for the demo fixture. Do not deploy.
import express from 'express';
import { exec } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

router.get('/export', requireAuth, exportReport);
router.get('/files/:name', readUpload);
router.get('/preview', previewUrl);

function exportReport(req, res) {
  // Shell command built from a query parameter.
  exec(`tar -czf /tmp/report.tgz ${req.query.dir}`, (err) => {
    res.json({ ok: !err });
  });
}

function readUpload(req, res) {
  const target = path.join('uploads', req.params.name);
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) return res.status(404).end();
    res.type('text/plain').send(data);
  });
}

async function previewUrl(req, res) {
  const upstream = await fetch(String(req.query.url));
  res.send(await upstream.text());
}

export default router;
