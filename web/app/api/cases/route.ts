import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { AuthorizationError } from "@/src/auth/authorization";
import { getAppSession } from "@/src/auth/session";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const config = parseRuntimeConfig(process.env);
  if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });
  if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
    return NextResponse.json({ error: "JSON_REQUIRED" }, { status: 415 });
  }
  try {
    const body = (await request.json()) as { title?: unknown };
    const item = await new AppStore(getLocalDatabase(config)).createCase(session.user.id, body.title);
    return NextResponse.json(item, { status: 201 });
  } catch (error) {
    if (error instanceof AuthorizationError) return NextResponse.json({ error: error.code }, { status: 403 });
    if (error instanceof ZodError || error instanceof SyntaxError) return NextResponse.json({ error: "INVALID_CASE" }, { status: 400 });
    throw error;
  }
}
