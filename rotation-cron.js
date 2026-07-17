import cron from "node-cron";
import db from "./db.js";
import { generateClientSecret, hashSecret } from "./crypto-utils.js";

const ROTATION_INTERVAL_DAYS = Number(process.env.ROTATION_INTERVAL_DAYS || 30);
const TOKEN_RETENTION_DAYS = Number(process.env.TOKEN_RETENTION_DAYS || 7);

function logAudit(agentId, action, detail) {
  db.prepare(
    `INSERT INTO audit_log (agent_id, action, detail) VALUES (?, ?, ?)`
  ).run(agentId, action, JSON.stringify(detail || {}));
}


function rotateStaleSecrets() {
  const staleAgents = db
    .prepare(
      `SELECT id, name, created_at FROM agents
       WHERE status = 'active'
       AND datetime(created_at) <= datetime('now', ?)`
    )
    .all(`-${ROTATION_INTERVAL_DAYS} days`);

  for (const agent of staleAgents) {
    const newSecret = generateClientSecret();
    const newHash = hashSecret(newSecret);

    db.prepare(`UPDATE agents SET client_secret_hash = ?, created_at = datetime('now') WHERE id = ?`)
      .run(newHash, agent.id);

    // In prod: push newSecret to Vault + notify owner. Never log the raw secret.
    logAudit(agent.id, "SECRET_ROTATED", {
      rotated_at: new Date().toISOString(),
      note: "old secret invalidated, new secret delivered out-of-band",
    });

    console.log(`[rotation] Rotated secret for ${agent.name} (${agent.id})`);
  }

  return staleAgents.length;
}


function pruneExpiredTokens() {
  const result = db
    .prepare(
      `DELETE FROM issued_tokens
       WHERE datetime(expires_at) <= datetime('now', ?)`
    )
    .run(`-${TOKEN_RETENTION_DAYS} days`);

  if (result.changes > 0) {
    console.log(`[cleanup] Pruned ${result.changes} expired token records`);
  }
  return result.changes;
}

export function startCronJobs() {
  // Daily at 2 AM: rotate stale secrets
  cron.schedule("0 2 * * *", () => {
    const count = rotateStaleSecrets();
    console.log(`[rotation] Cron run complete. ${count} agent(s) rotated.`);
  });

  // Hourly: prune expired tokens
  cron.schedule("0 * * * *", () => {
    pruneExpiredTokens();
  });

  console.log("Cron jobs scheduled: rotation (daily 2AM), cleanup (hourly)");
}

// Allow manual trigger for demo purposes: `node rotation-cron.js --run-now`
if (process.argv.includes("--run-now")) {
  console.log("Running rotation + cleanup immediately (demo mode)...");
  const rotated = rotateStaleSecrets();
  const pruned = pruneExpiredTokens();
  console.log(`Done. Rotated: ${rotated}, Pruned: ${pruned}`);
}