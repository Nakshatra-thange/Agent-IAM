export function requireAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];
    if (!key || key !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({ error: "invalid or missing admin key" });
    }
    next();
  }