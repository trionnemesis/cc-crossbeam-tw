import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sanitizeReturnTo } from "@/src/auth/redirect";
import { LineLinkService, verifyLineSignature } from "@/src/channels/line";
import { createMemoryDatabase } from "@/src/db/local";
import { channelIdentity, user } from "@/src/db/schema";

describe("LINE account linking", () => {
  it("verifies the untouched raw body signature", () => {
    const body = JSON.stringify({ events: [{ type: "accountLink" }] });
    const secret = "line-channel-secret";
    const signature = createHmac("sha256", secret).update(body).digest("base64");
    expect(verifyLineSignature(body, signature, secret)).toBe(true);
    expect(verifyLineSignature(`${body} `, signature, secret)).toBe(false);
  });

  it("links one channel identity and rejects nonce replay", async () => {
    const database = createMemoryDatabase();
    const userId = randomUUID();
    database.db.insert(user).values({ id: userId, name: "Owner", email: "owner@example.test" }).run();
    const service = new LineLinkService(database);
    const challenge = await service.createAuthenticatedChallenge(userId, "L".repeat(32));
    const nonce = new URL(challenge.redirectUrl).searchParams.get("nonce");
    expect(nonce).toBeTruthy();
    await expect(service.completeFromWebhook("U-line-user", nonce!, "ok")).resolves.toMatchObject({ userId });
    await expect(service.completeFromWebhook("U-line-user", nonce!, "ok")).rejects.toThrow("REPLAY_OR_EXPIRED");
    const identities = database.db.select().from(channelIdentity).all();
    expect(identities).toHaveLength(1);
    expect(identities[0]).toMatchObject({ channel: "line", userId, unlinkedAt: null });
    await expect(service.isLinked(userId)).resolves.toBe(true);
    await expect(service.unlink(userId)).resolves.toEqual({ unlinked: 1 });
    await expect(service.isLinked(userId)).resolves.toBe(false);
    database.sqlite.close();
  });
});

describe("post-login redirect", () => {
  it("keeps an internal LINE callback and rejects external redirects", () => {
    expect(sanitizeReturnTo("/link/line?linkToken=abc")).toBe("/link/line?linkToken=abc");
    expect(sanitizeReturnTo("https://evil.example/steal")).toBe("/cases");
    expect(sanitizeReturnTo("//evil.example/steal")).toBe("/cases");
  });
});
