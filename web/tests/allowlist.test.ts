import { afterEach, describe, expect, it } from "vitest";
import { isIdentityAllowed, type InviteReader } from "@/src/auth/allowlist";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { revokeUserSessions } from "@/src/auth/session";
import { createMemoryDatabase, type LocalDatabase } from "@/src/db/local";
import { session as sessionTable, user } from "@/src/db/schema";

let database: LocalDatabase | undefined;

afterEach(() => {
  database?.sqlite.close();
  database = undefined;
});

const invites = (allowed: string[]): InviteReader => ({
  isInvitedEmail: async (email) => allowed.includes(email.trim().toLowerCase())
});

const localConfig = parseRuntimeConfig({ APP_MODE: "local" });

const singleUserConfig = parseRuntimeConfig({
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

describe("owner allowlist", () => {
  it("matches the owner case-insensitively and rejects everyone else", async () => {
    const none = invites([]);
    await expect(
      isIdentityAllowed(singleUserConfig, none, { email: "OWNER@Example.test " })
    ).resolves.toBe(true);
    await expect(
      isIdentityAllowed(singleUserConfig, none, { email: "intruder@example.test" })
    ).resolves.toBe(false);
    // An invitation must not become a back door around single-user ownership.
    await expect(
      isIdentityAllowed(singleUserConfig, invites(["intruder@example.test"]), {
        email: "intruder@example.test"
      })
    ).resolves.toBe(false);
  });

  it("rejects an identity with no email, and anonymous accounts outside local mode", async () => {
    const none = invites([]);
    await expect(isIdentityAllowed(singleUserConfig, none, { email: null })).resolves.toBe(false);
    await expect(isIdentityAllowed(singleUserConfig, none, { isAnonymous: true })).resolves.toBe(
      false
    );
    await expect(isIdentityAllowed(localConfig, none, { isAnonymous: true })).resolves.toBe(true);
  });

  it("follows the invitation list when it is the active policy", async () => {
    await expect(
      isIdentityAllowed(localConfig, invites(["guest@example.test"]), {
        email: "guest@example.test"
      })
    ).resolves.toBe(true);
    await expect(
      isIdentityAllowed(localConfig, invites([]), { email: "guest@example.test" })
    ).resolves.toBe(false);
  });
});

describe("session revocation", () => {
  it("drops every session the revoked user holds, and no one else's", () => {
    database = createMemoryDatabase();
    const now = new Date();
    for (const id of ["revoked", "kept"]) {
      database.db
        .insert(user)
        .values({ id, name: id, email: `${id}@example.test`, createdAt: now, updatedAt: now })
        .run();
    }
    const expiresAt = new Date(Date.now() + 3_600_000);
    for (const [id, userId] of [
      ["s1", "revoked"],
      ["s2", "revoked"],
      ["s3", "kept"]
    ]) {
      database.db
        .insert(sessionTable)
        .values({ id, userId, token: `token-${id}`, expiresAt, createdAt: now, updatedAt: now })
        .run();
    }

    revokeUserSessions(database, "revoked");

    const remaining = database.db.select({ id: sessionTable.id }).from(sessionTable).all();
    expect(remaining.map((row) => row.id)).toEqual(["s3"]);
  });
});
