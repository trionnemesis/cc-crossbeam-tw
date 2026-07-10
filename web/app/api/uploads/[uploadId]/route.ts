import { NextResponse } from "next/server";
import { getAppSession } from "@/src/auth/session";
import { AuthorizationError } from "@/src/auth/authorization";
import { getUploadService } from "@/src/uploads/factory";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  context: { params: Promise<{ uploadId: string }> }
) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  try {
    const { uploadId } = await context.params;
    const upload = await getUploadService().getStatus(session.user.id, uploadId);
    if (!upload) return NextResponse.json({ error: "NOT_FOUND" }, { status: 404 });
    return NextResponse.json(upload, {
      headers: { "cache-control": "no-store, max-age=0" }
    });
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return NextResponse.json({ error: error.code }, { status: 403 });
    }
    throw error;
  }
}
