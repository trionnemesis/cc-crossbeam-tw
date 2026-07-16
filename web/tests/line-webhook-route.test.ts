import { createHmac } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const lineSpies = vi.hoisted(() => ({
  complete: vi.fn(),
  requestToken: vi.fn(),
  reply: vi.fn()
}));

vi.mock("@/src/channels/line", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/src/channels/line")>();
  return {
    ...original,
    LineLinkService: class {
      completeFromWebhook = lineSpies.complete;
    },
    LineMessagingClient: class {
      requestLinkToken = lineSpies.requestToken;
      replyWithSecureLink = lineSpies.reply;
    }
  };
});
vi.mock("@/src/config/runtime", () => ({
  parseRuntimeConfig: vi.fn(() => ({
    APP_ORIGIN: "https://secure.example.com",
    LINE_CHANNEL_SECRET: "line-channel-secret"
  }))
}));
vi.mock("@/src/db/local", () => ({ getLocalDatabase: vi.fn(() => ({})) }));

import { POST } from "@/app/api/channels/line/webhook/route";

function request(body: string, signature?: string, contentLength = String(Buffer.byteLength(body))) {
  return new Request("https://secure.example.com/api/channels/line/webhook", {
    method: "POST",
    headers: {
      "content-length": contentLength,
      "content-type": "application/json",
      "x-line-signature": signature ?? createHmac("sha256", "line-channel-secret").update(body).digest("base64")
    },
    body
  });
}

describe("LINE webhook route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    lineSpies.requestToken.mockResolvedValue("L".repeat(32));
    lineSpies.reply.mockResolvedValue(undefined);
    lineSpies.complete.mockResolvedValue({ userId: "owner" });
  });

  it("rejects oversized and modified signed bodies", async () => {
    const body = JSON.stringify({ events: [] });
    expect((await POST(request(body, undefined, "262145"))).status).toBe(413);
    const signature = createHmac("sha256", "line-channel-secret").update(body).digest("base64");
    expect((await POST(request(`${body} `, signature))).status).toBe(401);
  });

  it("processes the raw signed message entry flow", async () => {
    const body = JSON.stringify({
      events: [{
        type: "message",
        replyToken: "reply-token",
        source: { userId: "U-line-user" }
      }]
    });
    const response = await POST(request(body));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ accepted: true });
    expect(lineSpies.requestToken).toHaveBeenCalledWith("U-line-user");
    expect(lineSpies.reply).toHaveBeenCalledWith(
      "reply-token",
      expect.stringContaining("https://secure.example.com/link/line?linkToken=")
    );
  });

  it("returns a bounded failure when the Messaging API fails", async () => {
    lineSpies.reply.mockRejectedValueOnce(new Error("network details must not escape"));
    const body = JSON.stringify({
      events: [{ type: "message", replyToken: "reply-token", source: { userId: "U-line-user" } }]
    });
    const response = await POST(request(body));
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({ error: "LINE_EVENT_FAILED" });
  });
});
