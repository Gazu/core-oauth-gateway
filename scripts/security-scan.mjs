import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.cwd();
const ignoredDirs = new Set([
  ".git",
  ".next",
  "node_modules",
  "dist",
  "out",
  "coverage",
  "secrets"
  ,"keystore"
]);
const ignoredFiles = new Set([
  "package-lock.json"
]);
const ignoredPaths = new Set([
  "scripts/security-scan.mjs"
]);
const ignoredFilePatterns = [
  /^\.env(?:\.|$)/,
  /\.log$/,
  /\.tsbuildinfo$/
];
const forbiddenFilePatterns = [
  /\.jks$/,
  /\.pem$/,
  /\.p12$/,
  /\.pfx$/,
  /\.key$/
];
const forbiddenContentPatterns = [
  { name: "private key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "hardcoded UUID client id", pattern: /client[-_]?id["'\s:=]+[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i },
  { name: "hardcoded keystore password", pattern: /(?:storepass|keypass)\s*[:=]\s*["'](?!\$|<)[^"']{8,}/i },
  { name: "basic auth example with inline secret", pattern: /-u\s+[^:\s]+:[^<\s]+/ },
  { name: "Supabase JWT assigned to env", pattern: /SUPABASE_(?:SERVICE_ROLE_)?KEY\s*=\s*eyJ[a-zA-Z0-9_-]+\./ },
  { name: "long RSA public key fixture", pattern: /MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A/ }
];

const findings = [];

walk(root);

if (findings.length) {
  console.error("Security scan failed:");
  for (const finding of findings) {
    console.error(`- ${finding}`);
  }
  process.exit(1);
}

console.log("Security scan passed.");

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const rel = relative(root, path);
    const stat = statSync(path);

    if (stat.isDirectory()) {
      if (!ignoredDirs.has(entry)) walk(path);
      continue;
    }

    if (!stat.isFile()) continue;
    if (ignoredPaths.has(rel)) continue;
    if (ignoredFiles.has(entry)) continue;
    if (ignoredFilePatterns.some((pattern) => pattern.test(entry))) continue;

    if (forbiddenFilePatterns.some((pattern) => pattern.test(entry))) {
      findings.push(`${rel}: sensitive file extension should not be versioned`);
      continue;
    }

    let content;
    try {
      content = readFileSync(path, "utf8");
    } catch {
      continue;
    }

    for (const { name, pattern } of forbiddenContentPatterns) {
      if (pattern.test(content)) findings.push(`${rel}: ${name}`);
    }
  }
}
