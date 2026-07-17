import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import db from "./db.js";
import { generateClientSecret, hashSecret, verifySecret } from "./crypto-utils.js";

dotenv.config();
const app = express();
app.use(express.json());

const {
  PORT = 4000,
  JWT_SECRET,
  JWT_PRIVATE_ISSUER,
  DEFAULT_TOKEN_TTL_SECONDS = 900,
} = process.env;

function logAudit(agentId, action, detail) {
  db.prepare(
    `INSERT INTO audit_log (agent_id, action, detail) VALUES (?, ?, ?)`
  ).run(agentId, action, JSON.stringify(detail || {}));
}

app.post("/agents/register", (req, res) => {
  const { name, allowed_scopes } = req.body;

  if (!name || !Array.isArray(allowed_scopes) || allowed_scopes.length === 0) {
    return res.status(400).json({ error: "name and allowed_scopes[] are required" });
  }

  const id = "agent_" + uuidv4();
  const clientSecret = generateClientSecret();
  const secretHash = hashSecret(clientSecret);

  db.prepare(
    `INSERT INTO agents (id, name, client_secret_hash, allowed_scopes) VALUES (?, ?, ?, ?)`
  ).run(id, name, secretHash, JSON.stringify(allowed_scopes));

  logAudit(id, "AGENT_REGISTERED", { name, allowed_scopes });

  return res.status(201).json({
    agent_id: id,
    name,
    client_secret: clientSecret, // shown once, never again
    allowed_scopes,
    warning: "Store client_secret now — it will not be shown again.",
  });
});

/**
 * POST /agents/:id/token
 * Body: { client_secret: "...", system: "github", scope: "github:pr:write", ttl_seconds?: 300 }
 * Issues a short-lived, scoped JWT for a SPECIFIC system + scope (not a blanket token).
 */
app.post("/agents/:id/token", (req, res) => {
  const { id } = req.params;
  const { client_secret, system, scope, ttl_seconds } = req.body;

  const agent = db.prepare(`SELECT * FROM agents WHERE id = ?`).get(id);
  if (!agent) return res.status(404).json({ error: "unknown agent" });
  if (agent.status !== "active") {
    logAudit(id, "TOKEN_DENIED_SUSPENDED", { system, scope });
    return res.status(403).json({ error: "agent is suspended" });
  }

  if (!verifySecret(client_secret, agent.client_secret_hash)) {
    logAudit(id, "TOKEN_DENIED_BAD_SECRET", { system, scope });
    return res.status(401).json({ error: "invalid client_secret" });
  }

  const allowedScopes = JSON.parse(agent.allowed_scopes);
  if (!allowedScopes.includes(scope)) {
    logAudit(id, "TOKEN_DENIED_SCOPE_NOT_ALLOWED", { requested: scope, allowed: allowedScopes });
    return res.status(403).json({
      error: `scope '${scope}' not permitted for this agent`,
      allowed_scopes: allowedScopes,
    });
  }

  const jti = uuidv4();
  const ttl = Math.min(Number(ttl_seconds) || DEFAULT_TOKEN_TTL_SECONDS, 3600); // hard cap 1hr
  const expiresAt = new Date(Date.now() + ttl * 1000);

  const token = jwt.sign(
    {
      sub: agent.id,
      name: agent.name,
      system,
      scope,
      jti,
    },
    JWT_SECRET,
    {
      issuer: JWT_PRIVATE_ISSUER,
      expiresIn: ttl,
    }
  );

  db.prepare(
    `INSERT INTO issued_tokens (jti, agent_id, scope, system, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(jti, agent.id, scope, system, expiresAt.toISOString());

  logAudit(agent.id, "TOKEN_ISSUED", { system, scope, jti, ttl });

  return res.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: ttl,
    scope,
    system,
    jti,
  });
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Agent IAM running on http://localhost:${PORT}`);
});