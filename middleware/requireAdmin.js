module.exports = function requireAdmin(req, res, next) {
  if (!req.session?.userId || req.session?.userRole !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
