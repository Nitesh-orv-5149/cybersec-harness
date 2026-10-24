export function requireAuth(req, res, next) {
  if (req.get('x-demo-user')) return next();
  res.status(401).json({ error: 'auth required' });
}
