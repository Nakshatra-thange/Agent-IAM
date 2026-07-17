import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

export function generateClientSecret() {
  return "sk_agent_" + uuidv4().replace(/-/g, "") + uuidv4().slice(0, 8);
}

export function hashSecret(secret) {
  return bcrypt.hashSync(secret, 10);
}

export function verifySecret(secret, hash) {
  return bcrypt.compareSync(secret, hash);
}