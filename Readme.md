# AgentIAM — Identity & Access Management for AI Agents

Problem: AI agents that act inside real systems (GitHub, Slack, payment
APIs) are usually given static, long-lived API keys with broad scope.
One leaked key = full access to everything the agent could ever touch.

AgentIAM issues short-lived, scoped, revocable credentials per agent
per system — the same pattern human IAM (Okta, AWS IAM) uses, applied
to autonomous workers.

## What it does
- Register an agent → get a client_id/secret (like an IAM user)
- Request scoped tokens per system (github:pr:write ≠ github:repo:read)
- Middleware any resource server can drop in to enforce scope
- Instant revocation — single token OR entire agent, live requests included
- Auto-rotation of stale secrets + audit log of every issuance/denial

## Architecture


## Run it
# 1. Clone and install
git clone https://github.com/Nakshatra-thange/Agent-IAM
cd agent-iam
npm install

# 2. Set up environment
cp .env.example .env
# then edit .env and set:
#   JWT_SECRET=<long random string, 32+ chars>
#   ADMIN_API_KEY=<long random string>

# 3. Start the IAM server (Part 1 + Part 3 routes)
npm start
# → running on http://localhost:4000

# 4. In a second terminal, start the mock resource server (Part 2)
node mock-resource-server.js
# → running on http://localhost:5000

# 5.  Run the rotation cron manually to see it work without waiting
node rotation-cron.js --run-now

## Why this matters
As companies deploy AI "digital employees" (see: Paddox, Sierra, etc.),
credential sprawl becomes the actual security risk — not model behavior.
This is the identity layer that makes an agent workforce auditable.