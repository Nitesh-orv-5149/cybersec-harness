import { test } from 'node:test';
import assert from 'node:assert/strict';
import { orderService } from '../src/services/orderService.js';
import { formatCurrency } from '../src/lib/format.js';
import { validateOrderInput } from '../src/lib/validate.js';

test('lists seeded orders with formatted totals', () => {
  const orders = orderService.list();
  assert.equal(orders.length >= 3, true);
  assert.equal(orders[0].total, '₹8499.00');
});

test('formats paise as rupees', () => {
  assert.equal(formatCurrency(12345), '₹123.45');
});

test('rejects an order without an item', () => {
  assert.deepEqual(validateOrderInput({ cents: 100 }), ['item is required']);
});
