import express from 'express';
import { db } from '../lib/db.js';

const router = express.Router();

router.get('/items/search', searchItems);
router.get('/items/:id', getItem);

// Test fixture: builds SQL from a query parameter so the API test has something to find.
function searchItems(req, res) {
  const rows = db.query(`SELECT * FROM items WHERE name = '${req.query.q ?? ''}'`);
  res.json(rows);
}

function getItem(req, res) {
  const item = db.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
}

export default router;
