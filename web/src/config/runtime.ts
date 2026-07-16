import { z } from "zod";

const loopbackOrigin = z
  .string()
  .url()
  .refine((value) => {
    const host = new URL(value).hostname;
    return host === "127.0.0.1" || host === "localhost" || host === "::1";
  }, "local APP_ORIGIN must use a loopback host");

const baseSchema = z.object({
  APP_MODE: z.enum(["local", "single-user", "production"]).default("local"),
  APP_ORIGIN: z.string().url().default("http://127.0.0.1:3000"),
  LOCAL_AUTH_EMAIL: z.string().email().optional(),
  DATABASE_PATH: z.string().default("../.runtime/secure-web.sqlite"),
  QUARANTINE_ROOT: z.string().default("../.runtime/quarantine"),
  SANITIZED_ROOT: z.string().default("../.runtime/sanitized"),
  LOCAL_WORKER_ORIGIN: z.string().url().default("http://127.0.0.1:8787"),
  WORKER_UPLOAD_ORIGIN: z.string().url().default("http://127.0.0.1:8787"),
  CODEX_WORKER_ENABLED: z.enum(["true", "false"]).default("false"),
  OWNER_EMAIL: z.string().email().optional(),
  GOOGLE_CLIENT_ID: z.string().min(1).optional(),
  GOOGLE_CLIENT_SECRET: z.string().min(1).optional(),
  LINE_CHANNEL_ID: z.string().min(1).optional(),
  LINE_CHANNEL_SECRET: z.string().min(1).optional(),
  LINE_CHANNEL_ACCESS_TOKEN: z.string().min(1).optional(),
  BETTER_AUTH_SECRET: z.string().min(32).optional(),
  DATABASE_URL: z.string().url().optional(),
  GCS_QUARANTINE_BUCKET: z.string().min(3).optional(),
  GCS_SANITIZED_BUCKET: z.string().min(3).optional(),
  GCP_TASKS_QUEUE: z.string().min(1).optional()
});

export type RuntimeConfig = z.infer<typeof baseSchema>;

const productionKeys = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "LINE_CHANNEL_ID",
  "LINE_CHANNEL_SECRET",
  "LINE_CHANNEL_ACCESS_TOKEN",
  "BETTER_AUTH_SECRET",
  "DATABASE_URL",
  "GCS_QUARANTINE_BUCKET",
  "GCS_SANITIZED_BUCKET",
  "GCP_TASKS_QUEUE"
] as const satisfies ReadonlyArray<keyof RuntimeConfig>;

export function parseRuntimeConfig(
  environment: Readonly<Record<string, string | undefined>>
): RuntimeConfig {
  const localDefaults = (environment.APP_MODE ?? "local") === "local"
    ? { LOCAL_AUTH_EMAIL: environment.LOCAL_AUTH_EMAIL ?? "owner@local.invalid" }
    : {};
  const parsed = baseSchema.parse({ ...environment, ...localDefaults });

  if (parsed.APP_MODE === "local") {
    loopbackOrigin.parse(parsed.APP_ORIGIN);
    loopbackOrigin.parse(parsed.LOCAL_WORKER_ORIGIN);
    loopbackOrigin.parse(parsed.WORKER_UPLOAD_ORIGIN);
    if (!parsed.LOCAL_AUTH_EMAIL) {
      throw new Error("LOCAL_AUTH_EMAIL is required in local mode");
    }
    return parsed;
  }

  if (parsed.APP_MODE === "single-user") {
    const missing = [
      "OWNER_EMAIL",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
      "LINE_CHANNEL_ID",
      "LINE_CHANNEL_SECRET",
      "LINE_CHANNEL_ACCESS_TOKEN",
      "BETTER_AUTH_SECRET"
    ].filter((key) => !parsed[key as keyof RuntimeConfig]);
    if (missing.length > 0) {
      throw new Error(`Missing single-user configuration: ${missing.join(", ")}`);
    }
    const origin = new URL(parsed.APP_ORIGIN);
    const uploadOrigin = new URL(parsed.WORKER_UPLOAD_ORIGIN);
    if (origin.protocol !== "https:" || uploadOrigin.protocol !== "https:") {
      throw new Error("single-user public origins must use HTTPS");
    }
    if (
      origin.origin !== uploadOrigin.origin ||
      uploadOrigin.username ||
      uploadOrigin.password ||
      uploadOrigin.search ||
      uploadOrigin.hash ||
      uploadOrigin.pathname.replace(/\/$/, "") !== "/worker"
    ) {
      throw new Error("single-user upload endpoint must be the same-origin /worker path");
    }
    loopbackOrigin.parse(parsed.LOCAL_WORKER_ORIGIN);
    if (parsed.LOCAL_AUTH_EMAIL) {
      throw new Error("LOCAL_AUTH_EMAIL bypass is forbidden in single-user mode");
    }
    return parsed;
  }

  const missing = productionKeys.filter((key) => !parsed[key]);
  if (missing.length > 0) {
    throw new Error(`Missing production configuration: ${missing.join(", ")}`);
  }
  if (parsed.LOCAL_AUTH_EMAIL) {
    throw new Error("LOCAL_AUTH_EMAIL is forbidden in production");
  }
  if (parsed.CODEX_WORKER_ENABLED === "true") {
    throw new Error("Codex CLI provider is forbidden in production");
  }
  if (parsed.GCS_QUARANTINE_BUCKET === parsed.GCS_SANITIZED_BUCKET) {
    throw new Error("Production quarantine and sanitized buckets must be distinct");
  }
  return parsed;
}

export function safeConfigSummary(config: RuntimeConfig) {
  return {
    mode: config.APP_MODE,
    origin: config.APP_ORIGIN,
    codexWorkerEnabled: config.CODEX_WORKER_ENABLED === "true",
    database: config.APP_MODE === "production" ? "postgresql" : "local-private",
    storage: config.APP_MODE === "production" ? "gcs-private" : "local-private"
  } as const;
}
