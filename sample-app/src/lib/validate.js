export function validateOrderInput(body) {
  const problems = [];
  if (!body || typeof body.item !== 'string' || body.item.trim() === '') problems.push('item is required');
  if (!body || !Number.isInteger(body.cents) || body.cents <= 0) problems.push('cents must be a positive integer');
  return problems;
}
