import express from 'express';
import { orderService } from '../services/orderService.js';
import { requireAuth } from '../middleware/auth.js';
import { validateOrderInput } from '../lib/validate.js';

const router = express.Router();

router.get('/orders', listOrders);
router.get('/orders/:id', getOrder);
router.post('/orders', requireAuth, createOrder);
router.get('/orders/:id/receipt', (req, res) => {
  const order = orderService.fetch(req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(orderService.receipt(order));
});

function listOrders(req, res) {
  res.json(orderService.list());
}

function getOrder(req, res) {
  const order = orderService.fetch(req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
}

function createOrder(req, res) {
  const problems = validateOrderInput(req.body);
  if (problems.length) return res.status(400).json({ errors: problems });
  res.status(201).json(orderService.create(req.body));
}

export default router;
