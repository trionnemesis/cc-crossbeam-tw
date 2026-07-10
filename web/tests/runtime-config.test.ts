import { describe, expect, it } from "vitest";
import { parseRuntimeConfig, safeConfigSummary } from "@/src/config/runtime";

describe("runtime configuration", () => {
  it("allows a loopback-only local pilot without production secrets", () => {
    const config = parseRuntimeConfig({
      APP_MODE: "local",
      APP_ORIGIN: "http://127.0.0.1:3000",
      LOCAL_AUTH_EMAIL: "owner@example.test",
      CODEX_WORKER_ENABLED: "true"
    });

    expect(safeConfigSummary(config)).toEqual({
      mode: "local",
      origin: "http://127.0.0.1:3000",
      codexWorkerEnabled: true,
      database: "local-private",
      storage: "local-private"
    });
  });

  it("rejects a network-reachable local bypass origin", () => {
    expect(() =>
      parseRuntimeConfig({
        APP_MODE: "local",
        APP_ORIGIN: "https://pilot.example.com",
        LOCAL_AUTH_EMAIL: "owner@example.test"
      })
    ).toThrow("loopback");
  });

  it("rejects incomplete production configuration", () => {
    expect(() =>
      parseRuntimeConfig({
        APP_MODE: "production",
        APP_ORIGIN: "https://secure.example.com"
      })
    ).toThrow("Missing production configuration");
  });

  it("allows a credential-complete HTTPS single-user host", () => {
    const config = parseRuntimeConfig({
      APP_MODE: "single-user",
      APP_ORIGIN: "https://secure.example.com",
      WORKER_UPLOAD_ORIGIN: "https://secure.example.com/worker",
      LOCAL_WORKER_ORIGIN: "http://127.0.0.1:8787",
      OWNER_EMAIL: "owner@example.test",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      LINE_CHANNEL_ID: "line-channel",
      LINE_CHANNEL_SECRET: "line-secret",
      LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
      BETTER_AUTH_SECRET: "x".repeat(32),
      CODEX_WORKER_ENABLED: "true"
    });
    expect(safeConfigSummary(config)).toMatchObject({
      mode: "single-user",
      codexWorkerEnabled: true,
      database: "local-private",
      storage: "local-private"
    });
  });

  it("rejects non-HTTPS single-user public origins", () => {
    expect(() =>
      parseRuntimeConfig({
        APP_MODE: "single-user",
        APP_ORIGIN: "http://secure.example.com",
        WORKER_UPLOAD_ORIGIN: "http://secure.example.com/worker",
        LOCAL_WORKER_ORIGIN: "http://127.0.0.1:8787",
        OWNER_EMAIL: "owner@example.test",
        GOOGLE_CLIENT_ID: "google-client",
        GOOGLE_CLIENT_SECRET: "google-secret",
        LINE_CHANNEL_ID: "line-channel",
        LINE_CHANNEL_SECRET: "line-secret",
        LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
        BETTER_AUTH_SECRET: "x".repeat(32)
      })
    ).toThrow("must use HTTPS");
  });

  it("rejects a cross-origin or unexpected single-user upload endpoint", () => {
    const base = {
      APP_MODE: "single-user",
      APP_ORIGIN: "https://secure.example.com",
      LOCAL_WORKER_ORIGIN: "http://127.0.0.1:8787",
      OWNER_EMAIL: "owner@example.test",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      LINE_CHANNEL_ID: "line-channel",
      LINE_CHANNEL_SECRET: "line-secret",
      LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
      BETTER_AUTH_SECRET: "x".repeat(32)
    };
    expect(() => parseRuntimeConfig({ ...base, WORKER_UPLOAD_ORIGIN: "https://files.example.net/worker" }))
      .toThrow("same-origin /worker");
    expect(() => parseRuntimeConfig({ ...base, WORKER_UPLOAD_ORIGIN: "https://secure.example.com/uploads" }))
      .toThrow("same-origin /worker");
  });

  it("rejects local auth in production", () => {
    const production = {
      APP_MODE: "production",
      APP_ORIGIN: "https://secure.example.com",
      LOCAL_AUTH_EMAIL: "owner@example.test",
      CODEX_WORKER_ENABLED: "true",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      LINE_CHANNEL_ID: "line-channel",
      LINE_CHANNEL_SECRET: "line-secret",
      LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
      BETTER_AUTH_SECRET: "x".repeat(32),
      DATABASE_URL: "postgresql://user:password@db.example.com/app",
      GCS_QUARANTINE_BUCKET: "private-quarantine",
      GCS_SANITIZED_BUCKET: "private-sanitized",
      GCP_TASKS_QUEUE: "secure-web-worker"
    };

    expect(() => parseRuntimeConfig(production)).toThrow("LOCAL_AUTH_EMAIL is forbidden");
  });

  it("rejects Codex CLI in production", () => {
    expect(() => parseRuntimeConfig({
      APP_MODE: "production",
      APP_ORIGIN: "https://secure.example.com",
      CODEX_WORKER_ENABLED: "true",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      LINE_CHANNEL_ID: "line-channel",
      LINE_CHANNEL_SECRET: "line-secret",
      LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
      BETTER_AUTH_SECRET: "x".repeat(32),
      DATABASE_URL: "postgresql://user:password@db.example.com/app",
      GCS_QUARANTINE_BUCKET: "private-quarantine",
      GCS_SANITIZED_BUCKET: "private-sanitized",
      GCP_TASKS_QUEUE: "secure-web-worker"
    })).toThrow("Codex CLI provider is forbidden");
  });
});
