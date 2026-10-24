// Shared formatting helpers used by several endpoints.
export function formatCurrency(cents) {
  return `₹${(cents / 100).toFixed(2)}`;
}

export function formatDate(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}
