import "server-only";

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { RuntimeConfig } from "@/src/config/runtime";

function getOrCreateLocalSecret(fileName: string): string {
  const runtimeRoot = path.resolve(/* turbopackIgnore: true */ process.cwd(), "..", ".runtime");
  mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
  chmodSync(runtimeRoot, 0o700);
  const trustedRoot = realpathSync(runtimeRoot);
  const secretPath = path.join(trustedRoot, fileName);
  if (!existsSync(secretPath)) {
    writeFileSync(secretPath, randomBytes(48).toString("base64url"), {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });
  }
  chmodSync(secretPath, 0o600);
  return readFileSync(secretPath, "utf8").trim();
}

export function getAuthSecret(config: RuntimeConfig): string {
  if (config.APP_MODE !== "local") {
    if (!config.BETTER_AUTH_SECRET) throw new Error("BETTER_AUTH_SECRET is required");
    return config.BETTER_AUTH_SECRET;
  }
  return getOrCreateLocalSecret("better-auth-secret");
}

export function getWorkerInternalSecret(config: RuntimeConfig): string {
  if (config.APP_MODE === "production") {
    throw new Error("Local worker secret is forbidden in production");
  }
  return getOrCreateLocalSecret("worker-internal-secret");
}
