import jwt from "jsonwebtoken";
import Database from "better-sqlite3";


const db = new Database("iam.db", { readonly: true });

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_PRIVATE_ISSUER;

export function requireScope(system, requiredScope) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "missing bearer token" });
    }

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET, { issuer: JWT_ISSUER });
    } catch (err) {
      return res.status(401).json({ error: "invalid or expired token", detail: err.message });
    }

    if (payload.system !== system) {
      return res.status(403).json({
        error: `token was issued for system '${payload.system}', not '${system}'`,
      });
    }


    if (payload.scope !== requiredScope) {
      return res.status(403).json({
        error: `token scope '${payload.scope}' does not grant '${requiredScope}'`,
      });
    }


    const record = db
      .prepare(`SELECT revoked FROM issued_tokens WHERE jti = ?`)
      .get(payload.jti);

    if (!record) {
      return res.status(401).json({ error: "token not recognized (never issued or DB mismatch)" });
    }
    if (record.revoked) {
      return res.status(401).json({ error: "token has been revoked" });
    }


    const agent = db
      .prepare(`SELECT status FROM agents WHERE id = ?`)
      .get(payload.sub);

    if (!agent || agent.status !== "active") {
      return res.status(403).json({ error: "issuing agent is suspended" });
    }

    req.agent = {
      id: payload.sub,
      name: payload.name,
      scope: payload.scope,
      system: payload.system,
      jti: payload.jti,
    };

    next();
  };
}