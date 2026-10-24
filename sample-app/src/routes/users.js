import express from 'express';
import { findUserByName, listUsers } from '../services/userService.js';

const router = express.Router();

router.get('/users', (req, res) => {
  res.json(listUsers());
});

router.get('/users/search', searchUsers);

function searchUsers(req, res) {
  res.json(findUserByName(String(req.query.q || '')));
}

export default router;
