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

  it("refuses a new session once the owner allowlist no longer covers the account", async () => {
    database = createMemoryDatabase();
    const singleUser = (ownerEmail: string) =>
      parseRuntimeConfig({
        APP_MODE: "single-user",
        APP_ORIGIN: "https://secure.example.com",
        WORKER_UPLOAD_ORIGIN: "https://secure.example.com/worker",
        LOCAL_WORKER_ORIGIN: "http://127.0.0.1:8787",
        OWNER_EMAIL: ownerEmail,
        GOOGLE_CLIENT_ID: "google-client",
        GOOGLE_CLIENT_SECRET: "google-secret",
        LINE_CHANNEL_ID: "line-channel",
        LINE_CHANNEL_SECRET: "line-secret",
        LINE_CHANNEL_ACCESS_TOKEN: "line-access-token",
        BETTER_AUTH_SECRET: "x".repeat(32)
      });
    const timestamps = { createdAt: new Date(), updatedAt: new Date() };

    const before = await buildAuth(singleUser("owner@example.test"), database, "x".repeat(48))
      .$context;
    const owner = await before.internalAdapter.createUser({
      name: "Owner",
      email: "owner@example.test",
      emailVerified: true,
      ...timestamps
    });
    expect(owner).not.toBeNull();
    await expect(
      before.internalAdapter.createSession(owner!.id)
    ).resolves.not.toBeNull();

    // Ownership moves to a different address; the old account still exists.
    const after = await buildAuth(singleUser("new-owner@example.test"), database, "x".repeat(48))
      .$context;
    await expect(
      after.internalAdapter.createSession(owner!.id)
    ).resolves.toBeNull();
  });
});
