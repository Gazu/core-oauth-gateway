import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const projectRoot = resolve(import.meta.dirname, "../..");
const appRoot = join(projectRoot, "src", "app");

describe("HTTP adapter structure", () => {
  it("keeps the Next App Router inside src", () => {
    expect(existsSync(appRoot)).toBe(true);
    expect(existsSync(join(projectRoot, "app"))).toBe(false);
  });

  it("keeps route handlers thin and controller-based", () => {
    const routes = collectRouteFiles(appRoot);
    expect(routes).toHaveLength(19);

    for (const route of routes) {
      const source = readFileSync(route, "utf8");
      expect(source).toContain("/interfaces/http/controllers/");
      expect(source).not.toContain("/oauth/service");
      expect(source).not.toContain("withOAuthRequestLogging");
    }
  });

  it("keeps domain and application independent from Next HTTP types", () => {
    const architectureRoots = [
      join(projectRoot, "src", "oauth", "domain"),
      join(projectRoot, "src", "oauth", "application")
    ];

    for (const root of architectureRoots) {
      for (const file of collectTypeScriptFiles(root)) {
        const source = readFileSync(file, "utf8");
        expect(source).not.toContain('from "next/server"');
        expect(source).not.toContain("NextRequest");
        expect(source).not.toMatch(/\bNextResponse\b/);
        expect(source).not.toMatch(/\bPromise<Response>\b/);
      }
    }
  });

  it("keeps application isolated from concrete infrastructure", () => {
    const applicationRoot = join(projectRoot, "src", "oauth", "application");
    const forbiddenImports = [
      "/infrastructure/",
      "@/oauth/logger",
      "@/oauth/store",
      "@/oauth/jwt",
      "@/oauth/audit"
    ];

    for (const file of collectTypeScriptFiles(applicationRoot)) {
      const source = readFileSync(file, "utf8");
      for (const forbiddenImport of forbiddenImports) {
        expect(source).not.toContain(forbiddenImport);
      }
    }
  });

  it("composes use cases in a single dependency container", () => {
    expect(existsSync(join(projectRoot, "src", "container.ts"))).toBe(true);
    expect(existsSync(join(projectRoot, "src", "oauth", "store.ts"))).toBe(false);
    expect(existsSync(join(projectRoot, "src", "oauth", "service.ts"))).toBe(false);
    expect(existsSync(join(projectRoot, "src", "oauth", "health.ts"))).toBe(false);

    const controllerRoot = join(projectRoot, "src", "oauth", "interfaces", "http", "controllers");
    for (const file of collectTypeScriptFiles(controllerRoot)) {
      if (file.endsWith("controller-support.ts")) continue;
      const source = readFileSync(file, "utf8");
      expect(source).toContain('from "@/container"');
      expect(source).not.toMatch(/new \w+UseCase\(/);
    }
  });

  it("implements token grants as application strategies", () => {
    const grantsRoot = join(
      projectRoot,
      "src",
      "oauth",
      "application",
      "services",
      "grants"
    );
    const strategies = readdirSync(grantsRoot).filter((file) => file.endsWith(".strategy.ts"));
    expect(strategies).toHaveLength(7);
  });
});

function collectRouteFiles(directory: string): string[] {
  const routes: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) routes.push(...collectRouteFiles(path));
    if (entry.isFile() && entry.name === "route.ts") routes.push(path);
  }
  return routes;
}

function collectTypeScriptFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...collectTypeScriptFiles(path));
    if (entry.isFile() && entry.name.endsWith(".ts")) files.push(path);
  }
  return files;
}
