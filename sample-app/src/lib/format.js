// Shared formatting helpers used by several endpoints.
export function formatCurrency(cents) {
  return `Rs ${Math.round(cents / 100)}`;
}

export function formatDate(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}
