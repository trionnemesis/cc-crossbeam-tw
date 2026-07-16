import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { AuthorizationError } from "@/src/auth/authorization";
import { getWorkerInternalSecret } from "@/src/auth/local-secret";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { getAppSession } from "@/src/auth/session";
import { WorkflowStore } from "@/src/cases/workflow-store";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  context: { params: Promise<{ questionId: string }> }
) {
  const session = await getAppSession();
  if (!session) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
    return NextResponse.json({ error: "JSON_REQUIRED" }, { status: 415 });
  }
  try {
    const config = parseRuntimeConfig(process.env);
    if (!isSameOriginMutation(request, config)) return NextResponse.json({ error: "ORIGIN_REJECTED" }, { status: 403 });
    const { questionId } = await context.params;
    const body = (await request.json()) as { answer?: unknown };
    const result = await new WorkflowStore(getLocalDatabase(config)).answerQuestion(
      session.user.id,
      questionId,
      body.answer
    );
    if (!result) return NextResponse.json({ error: "NOT_FOUND" }, { status: 404 });
    let reviewState = "awaiting_answers";
    if (result.allAnswered && !result.reviewCompleted) {
      const worker = await fetch(`${config.LOCAL_WORKER_ORIGIN}/review/${result.analysisRunId}`, {
        method: "POST",
        headers: { "x-worker-internal-secret": getWorkerInternalSecret(config) }
      });
      if (!worker.ok) return NextResponse.json({ error: "REVIEW_WORKER_FAILED" }, { status: 503 });
      reviewState = "completed";
    }
    return NextResponse.json({ saved: true, reviewState });
  } catch (error) {
    if (error instanceof AuthorizationError) return NextResponse.json({ error: error.code }, { status: 403 });
    if (error instanceof ZodError || error instanceof SyntaxError) return NextResponse.json({ error: "INVALID_ANSWER" }, { status: 400 });
    if (error instanceof Error && error.message === "QUESTION_ALREADY_RESOLVED") return NextResponse.json({ error: "ALREADY_RESOLVED" }, { status: 409 });
    throw error;
  }
}
