import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadPrivateKeyFromP12Base64 } from "@smb-tech/service-framework-js";

const p12Path = readOption("--p12") ?? readOption("--pfx");
const p12Base64 = p12Path
  ? readFileSync(p12Path).toString("base64")
  : process.env.CORE_OAUTH_P12_BASE64;
const plainPassword = readOption("--p12-password");
const p12PasswordBase64 =
  readOption("--p12-password-base64") ??
  process.env.CORE_OAUTH_P12_PASSWORD_BASE64 ??
  (plainPassword ? Buffer.from(plainPassword, "utf8").toString("base64") : undefined);
const p12Alias =
  readOption("--p12-alias") ?? process.env.CORE_OAUTH_P12_ALIAS;

if (!p12Base64 || !p12PasswordBase64 || !p12Alias) {
  fail(
    "Provide --p12, --p12-password and --p12-alias, or set " +
      "CORE_OAUTH_P12_BASE64, CORE_OAUTH_P12_PASSWORD_BASE64 and CORE_OAUTH_P12_ALIAS"
  );
}

const privateKey = loadPrivateKeyFromP12Base64({
  p12Base64,
  p12PasswordBase64,
  p12Alias
});
const publicKey = createPublicKey(privateKey);
const publicJwk = publicKey.export({ format: "jwk" });
const kid = createHash("sha256")
  .update(JSON.stringify({ kty: publicJwk.kty, n: publicJwk.n, e: publicJwk.e }))
  .digest("base64url");
const publicKeyDer = publicKey
  .export({ type: "spki", format: "der" })
  .toString("base64");

console.log(JSON.stringify({
  public_key: publicKeyDer,
  kid,
  jwks: {
    keys: [{ ...publicJwk, kid, alg: "RS256", use: "sig" }]
  }
}, null, 2));

function readOption(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
