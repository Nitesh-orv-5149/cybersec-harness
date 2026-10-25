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
  // Still fetches any caller-supplied URL (the SSRF this fixture demonstrates), but a missing or unreachable URL is
  // answered instead of crashing the whole server with an unhandled rejection.
  if (typeof req.query.url !== 'string' || !/^https?:\/\//i.test(req.query.url)) return res.status(400).json({ error: 'url query parameter (http or https) is required' });
  try {
    const upstream = await fetch(req.query.url);
    res.send(await upstream.text());
  } catch (err) {
    res.status(502).json({ error: `could not fetch url: ${err.message}` });
  }
}

export default router;
