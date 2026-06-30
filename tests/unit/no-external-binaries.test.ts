import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const forbiddenRuntimePatterns = [
  ["node:", "child_", "process"].join(""),
  ["from ", '"', "child_", "process", '"'].join(""),
  ["exec", "File", "Sync"].join(""),
  ["spawn", "Sync"].join("")
];

describe("runtime portability", () => {
  it("does not invoke external binaries", () => {
    const files = [
      ...sourceFiles(join(process.cwd(), "src")),
      ...sourceFiles(join(process.cwd(), "scripts"))
        .filter((path) => !path.endsWith("security-scan.mjs"))
    ];

    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const pattern of forbiddenRuntimePatterns) {
        expect(source, `${file} contains ${pattern}`).not.toContain(pattern);
      }
    }
  });

  it("uses only npm registry dependencies", () => {
    const packageJson = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    const dependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    } as Record<string, string>;

    expect(dependencies["@smb-tech/service-framework-js"]).toBe("0.2.0");
    for (const version of Object.values(dependencies)) {
      expect(version.startsWith("file:")).toBe(false);
      expect(version.startsWith("link:")).toBe(false);
    }
  });
});

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(?:[cm]?js|tsx?)$/.test(path) ? [path] : [];
  });
}
