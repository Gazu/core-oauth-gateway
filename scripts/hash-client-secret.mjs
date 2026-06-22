import { randomBytes, scryptSync } from "node:crypto";

const secret = readOption("--secret") ?? process.argv[2];
if (!secret) {
  console.error("Usage: npm run client:hash-secret -- --secret <client-secret>");
  process.exit(1);
}

const n = Number(readOption("--n") ?? 16384);
const r = Number(readOption("--r") ?? 8);
const p = Number(readOption("--p") ?? 1);
const salt = randomBytes(16);
const key = scryptSync(secret, salt, 64, { N: n, r, p });

console.log(["scrypt", String(n), String(r), String(p), salt.toString("base64url"), key.toString("base64url")].join("$"));

function readOption(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}
