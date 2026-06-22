import {
  JwksTokenVerifier,
  parseJwt
} from "@smb-tech/service-framework-js";

const args = process.argv.slice(2);
const token = args.find((argument) => !argument.startsWith("--")) ?? process.env.JWT;
const issuer = readOption("--issuer") ?? process.env.ISSUER;
const audience = readOption("--audience") ?? process.env.AUDIENCE;
const discoveryUrl = readOption("--discovery") ?? process.env.DISCOVERY_URL;
const jwksUrl = readOption("--jwks") ?? process.env.JWKS_URL;

if (!token) {
  fail("Missing JWT. Usage: npm run verify:jwt -- \"$JWT\" --issuer http://127.0.0.1:3000");
}
if (!jwksUrl && !discoveryUrl) {
  fail("Provide --jwks <url> or --discovery <url>");
}

try {
  const verifier = new JwksTokenVerifier({
    jwksUrl,
    discoveryUrl,
    expectedIssuer: issuer,
    expectedAudience: audience,
    allowedAlgorithms: ["RS256"],
    clockSkewSeconds: 30,
    cacheTtlMs: 300_000,
    timeoutMs: 10_000
  });
  const validated = await verifier.verify(token);
  const parsed = parseJwt(token);

  console.log(JSON.stringify({
    valid: true,
    signedByService: true,
    kid: parsed?.header.kid,
    alg: parsed?.header.alg,
    iss: validated.claims.iss,
    sub: validated.subject,
    aud: validated.claims.aud,
    exp: validated.expiresAt,
    scope: validated.claims.scope,
    client_id: validated.clientId
  }, null, 2));
} catch (error) {
  fail(error instanceof Error ? error.message : "JWT validation failed");
}

function readOption(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function fail(message) {
  console.error(JSON.stringify({ valid: false, error: message }, null, 2));
  process.exit(1);
}
