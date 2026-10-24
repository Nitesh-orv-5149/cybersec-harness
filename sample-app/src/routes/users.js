import express from 'express';
import { findUserByName, listUsers } from '../services/userService.js';
import { db } from '../lib/db.js';

const router = express.Router();

router.get('/users', (req, res) => {
  res.json(listUsers());
});

router.get('/users/search', searchUsers);

function searchUsers(req, res) {
  res.json(findUserByName(String(req.query.q || '')));
}

// Vulnerable endpoint: unsanitized raw SQL query using :id
router.get('/users/:id/profile', (req, res) => {
  const id = req.params.id;
  if (id.includes("'")) {
    throw new Error(`Uncaught SQL syntax error: unexpected quote in identifier "${id}"`);
  }
  const rows = db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows[0] || { id, status: 'unknown' });
});

// Vulnerable action: modifies user role without authentication
router.post('/users/:id/role', (req, res) => {
  res.json({ success: true, id: req.params.id, role: req.body?.role || 'admin' });
});

export default router;
