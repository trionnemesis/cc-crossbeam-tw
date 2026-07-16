import { NextResponse } from "next/server";
import { getAppSession } from "@/src/auth/session";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { LineLinkService } from "@/src/channels/line";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

export async function DELETE(request: Request) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const config = parseRuntimeConfig(process.env);
  if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });
  const result = await new LineLinkService(getLocalDatabase(config)).unlink(session.user.id);
  return NextResponse.json(result, { headers: { "cache-control": "no-store" } });
}
