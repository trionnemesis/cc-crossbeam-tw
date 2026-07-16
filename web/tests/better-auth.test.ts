import { afterEach, describe, expect, it } from "vitest";
import { buildAuth } from "@/src/auth/server";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { createMemoryDatabase, type LocalDatabase } from "@/src/db/local";

let database: LocalDatabase | undefined;

afterEach(() => {
  database?.sqlite.close();
  database = undefined;
});

describe("Better Auth local boundary", () => {
  it("creates a loopback anonymous session without exposing a production bypass", async () => {
    database = createMemoryDatabase();
    const config = parseRuntimeConfig({
      APP_MODE: "local",
      APP_ORIGIN: "http://127.0.0.1:3000"
    });
    const auth = buildAuth(config, database, "x".repeat(48));
    const response = await auth.handler(
      new Request("http://127.0.0.1:3000/api/auth/sign-in/anonymous", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://127.0.0.1:3000"
        },
        body: "{}"
      })
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("SameSite=Lax");
  });

  it("creates only the allowlisted owner in single-user mode", async () => {
    database = createMemoryDatabase();
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
      BETTER_AUTH_SECRET: "x".repeat(32)
    });
    const auth = buildAuth(config, database, "x".repeat(48));
    const context = await auth.$context;
    const timestamps = { createdAt: new Date(), updatedAt: new Date() };
    await expect(context.internalAdapter.createUser({
      name: "Owner",
      email: "OWNER@example.test",
      emailVerified: true,
      ...timestamps
    })).resolves.toMatchObject({ email: "owner@example.test" });
    await expect(context.internalAdapter.createUser({
      name: "Intruder",
      email: "intruder@example.test",
      emailVerified: true,
      ...timestamps
    })).resolves.toBeNull();
  });
});
