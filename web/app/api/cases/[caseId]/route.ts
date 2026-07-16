import { NextResponse } from "next/server";
import { AuthorizationError } from "@/src/auth/authorization";
import { getAppSession } from "@/src/auth/session";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { WorkflowStore } from "@/src/cases/workflow-store";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ caseId: string }> }
) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const config = parseRuntimeConfig(process.env);
  if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });
  try {
    const { caseId } = await context.params;
    const result = await new WorkflowStore(getLocalDatabase(config)).deleteCase(session.user.id, caseId);
    return NextResponse.json(result, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof AuthorizationError) return NextResponse.json({ error: error.code }, { status: 403 });
    if (error instanceof Error && error.message === "OWNER_REQUIRED") return NextResponse.json({ error: "OWNER_REQUIRED" }, { status: 403 });
    throw error;
  }
}
