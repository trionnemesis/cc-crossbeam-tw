import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { getAppSession } from "@/src/auth/session";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { AuthorizationError } from "@/src/auth/authorization";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getUploadService } from "@/src/uploads/factory";

export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  context: { params: Promise<{ caseId: string }> }
) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const config = parseRuntimeConfig(process.env);
  if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });

  const contentType = request.headers.get("content-type")?.split(";", 1)[0];
  if (contentType !== "application/json") {
    return NextResponse.json({ error: "JSON_METADATA_REQUIRED" }, { status: 415 });
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength <= 0 || contentLength > 16_384) {
    return NextResponse.json({ error: "INVALID_METADATA_SIZE" }, { status: 413 });
  }

  try {
    const { caseId } = await context.params;
    const intent = await getUploadService().createIntent(session.user.id, caseId, await request.json());
    return NextResponse.json(intent, { status: 201 });
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return NextResponse.json({ error: error.code }, { status: 403 });
    }
    if (error instanceof ZodError || error instanceof SyntaxError) {
      return NextResponse.json({ error: "INVALID_METADATA" }, { status: 400 });
    }
    throw error;
  }
}
