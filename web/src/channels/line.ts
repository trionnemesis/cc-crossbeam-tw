import "server-only";

import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { and, eq, isNull } from "drizzle-orm";
import type { RuntimeConfig } from "@/src/config/runtime";
import type { LocalDatabase } from "@/src/db/local";
import { auditEvent, channelIdentity, channelLinkChallenge } from "@/src/db/schema";

const CHALLENGE_TTL_MS = 8 * 60 * 1000;

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function verifyLineSignature(rawBody: string, signature: string, secret: string): boolean {
  if (!signature || !secret) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "base64");
  } catch {
    return false;
  }
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

export class LineLinkService {
  constructor(private readonly database: LocalDatabase) {}

  async createAuthenticatedChallenge(userId: string, linkToken: string) {
    if (!/^[A-Za-z0-9._~-]{20,512}$/.test(linkToken)) {
      throw new Error("INVALID_LINE_LINK_TOKEN");
    }
    const nonce = randomBytes(32).toString("base64url");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS);
    this.database.sqlite.transaction(() => {
      this.database.db
        .update(channelLinkChallenge)
        .set({ state: "expired", consumedAt: now })
        .where(
          and(
            eq(channelLinkChallenge.channel, "line"),
            eq(channelLinkChallenge.userId, userId),
            eq(channelLinkChallenge.state, "authenticated")
          )
        )
        .run();
      this.database.db.insert(channelLinkChallenge).values({
        id: randomUUID(),
        channel: "line",
        linkTokenHash: hash(linkToken),
        nonceHash: hash(nonce),
        userId,
        state: "authenticated",
        expiresAt,
        createdAt: now
      }).run();
    })();
    return {
      redirectUrl: `https://access.line.me/dialog/bot/accountLink?linkToken=${encodeURIComponent(linkToken)}&nonce=${encodeURIComponent(nonce)}`,
      expiresAt: expiresAt.toISOString()
    };
  }

  async completeFromWebhook(channelUserId: string, nonce: string, result: string) {
    if (!channelUserId || !nonce) throw new Error("INVALID_ACCOUNT_LINK_EVENT");
    const nonceHash = hash(nonce);
    const now = new Date();
    return this.database.sqlite.transaction(() => {
      const challenge = this.database.db
        .select()
        .from(channelLinkChallenge)
        .where(
          and(
            eq(channelLinkChallenge.channel, "line"),
            eq(channelLinkChallenge.nonceHash, nonceHash),
            eq(channelLinkChallenge.state, "authenticated")
          )
        )
        .get();
      if (!challenge || challenge.expiresAt.getTime() <= now.getTime()) {
        throw new Error("LINE_LINK_REPLAY_OR_EXPIRED");
      }
      if (result !== "ok") {
        this.database.db
          .update(channelLinkChallenge)
          .set({ state: "failed", consumedAt: now })
          .where(eq(channelLinkChallenge.id, challenge.id))
          .run();
        throw new Error("LINE_LINK_FAILED");
      }
      const existing = this.database.db
        .select()
        .from(channelIdentity)
        .where(
          and(
            eq(channelIdentity.channel, "line"),
            eq(channelIdentity.channelUserId, channelUserId)
          )
        )
        .get();
      if (existing && !existing.unlinkedAt && existing.userId !== challenge.userId) {
        throw new Error("LINE_IDENTITY_ALREADY_LINKED");
      }
      const identityId = existing?.id ?? randomUUID();
      if (existing) {
        this.database.db
          .update(channelIdentity)
          .set({ userId: challenge.userId, linkedAt: now, unlinkedAt: null })
          .where(eq(channelIdentity.id, existing.id))
          .run();
      } else {
        this.database.db.insert(channelIdentity).values({
          id: identityId,
          channel: "line",
          channelUserId,
          userId: challenge.userId,
          linkedAt: now
        }).run();
      }
      this.database.db
        .update(channelLinkChallenge)
        .set({ state: "linked", consumedAt: now })
        .where(eq(channelLinkChallenge.id, challenge.id))
        .run();
      this.database.db.insert(auditEvent).values({
        id: randomUUID(),
        caseId: null,
        actorUserId: challenge.userId,
        action: "channel.line.linked",
        entityType: "channel_identity",
        entityId: identityId,
        metadataJson: "{}",
        createdAt: now
      }).run();
      return { userId: challenge.userId, identityId };
    })();
  }

  async unlink(userId: string) {
    const now = new Date();
    const identities = await this.database.db
      .select({ id: channelIdentity.id })
      .from(channelIdentity)
      .where(
        and(
          eq(channelIdentity.channel, "line"),
          eq(channelIdentity.userId, userId),
          isNull(channelIdentity.unlinkedAt)
        )
      );
    for (const identity of identities) {
      await this.database.db
        .update(channelIdentity)
        .set({ unlinkedAt: now })
        .where(eq(channelIdentity.id, identity.id));
    }
    return { unlinked: identities.length };
  }

  async isLinked(userId: string): Promise<boolean> {
    const [identity] = await this.database.db
      .select({ id: channelIdentity.id })
      .from(channelIdentity)
      .where(
        and(
          eq(channelIdentity.channel, "line"),
          eq(channelIdentity.userId, userId),
          isNull(channelIdentity.unlinkedAt)
        )
      )
      .limit(1);
    return Boolean(identity);
  }
}

export class LineMessagingClient {
  constructor(private readonly config: RuntimeConfig) {}

  private get accessToken() {
    if (!this.config.LINE_CHANNEL_ACCESS_TOKEN) throw new Error("LINE_ACCESS_TOKEN_MISSING");
    return this.config.LINE_CHANNEL_ACCESS_TOKEN;
  }

  async requestLinkToken(lineUserId: string): Promise<string> {
    const response = await fetch(
      `https://api.line.me/v2/bot/user/${encodeURIComponent(lineUserId)}/linkToken`,
      { method: "POST", headers: { authorization: `Bearer ${this.accessToken}` } }
    );
    if (!response.ok) throw new Error("LINE_LINK_TOKEN_REQUEST_FAILED");
    const payload = (await response.json()) as { linkToken?: string };
    if (!payload.linkToken) throw new Error("LINE_LINK_TOKEN_MISSING");
    return payload.linkToken;
  }

  async replyWithSecureLink(replyToken: string, linkUrl: string): Promise<void> {
    const response = await fetch("https://api.line.me/v2/bot/message/reply", {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.accessToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        replyToken,
        messages: [{ type: "text", text: `開啟安全工作台：${linkUrl}` }]
      })
    });
    if (!response.ok) throw new Error("LINE_REPLY_FAILED");
  }
}
