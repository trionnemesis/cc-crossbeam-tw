import { NextResponse } from "next/server";
import { LineLinkService, LineMessagingClient, verifyLineSignature } from "@/src/channels/line";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

type LineEvent = {
  type?: string;
  replyToken?: string;
  source?: { userId?: string };
  link?: { nonce?: string; result?: string };
};

export async function POST(request: Request) {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(length) || length <= 0 || length > 262_144) return NextResponse.json({ error: "INVALID_BODY_SIZE" }, { status: 413 });
  const rawBody = await request.text();
  const config = parseRuntimeConfig(process.env);
  if (!config.LINE_CHANNEL_SECRET) return NextResponse.json({ error: "LINE_NOT_CONFIGURED" }, { status: 503 });
  if (!verifyLineSignature(rawBody, request.headers.get("x-line-signature") ?? "", config.LINE_CHANNEL_SECRET)) return NextResponse.json({ error: "INVALID_SIGNATURE" }, { status: 401 });

  let payload: { events?: LineEvent[] };
  try { payload = JSON.parse(rawBody) as { events?: LineEvent[] }; } catch { return NextResponse.json({ error: "INVALID_JSON" }, { status: 400 }); }
  const events = Array.isArray(payload.events) ? payload.events.slice(0, 20) : [];
  const service = new LineLinkService(getLocalDatabase(config));
  const client = new LineMessagingClient(config);
  try {
    for (const event of events) {
      const lineUserId = event.source?.userId;
      if (event.type === "accountLink" && lineUserId && event.link?.nonce) {
        await service.completeFromWebhook(lineUserId, event.link.nonce, event.link.result ?? "failed");
      } else if ((event.type === "message" || event.type === "postback") && lineUserId && event.replyToken) {
        const linkToken = await client.requestLinkToken(lineUserId);
        const linkUrl = `${config.APP_ORIGIN}/link/line?linkToken=${encodeURIComponent(linkToken)}&openExternalBrowser=1`;
        await client.replyWithSecureLink(event.replyToken, linkUrl);
      }
    }
  } catch {
    return NextResponse.json({ error: "LINE_EVENT_FAILED" }, { status: 409 });
  }
  return NextResponse.json({ accepted: true });
}
