import { NextResponse } from "next/server";
import { getAppSession } from "@/src/auth/session";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { LineLinkService } from "@/src/channels/line";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const config = parseRuntimeConfig(process.env);
  if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });
  if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") return NextResponse.json({ error: "JSON_REQUIRED" }, { status: 415 });
  try {
    const body = (await request.json()) as { linkToken?: string };
    const result = await new LineLinkService(getLocalDatabase(config)).createAuthenticatedChallenge(session.user.id, body.linkToken ?? "");
    return NextResponse.json(result, { status: 201, headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "INVALID_OR_EXPIRED_LINK" }, { status: 400 });
  }
}
