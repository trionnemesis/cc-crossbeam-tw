import { beforeEach, describe, expect, it, vi } from "vitest";

const answerQuestion = vi.hoisted(() => vi.fn());

vi.mock("@/src/auth/session", () => ({
  getAppSession: vi.fn(async () => ({ user: { id: "owner-user" } }))
}));
vi.mock("@/src/auth/local-secret", () => ({
  getWorkerInternalSecret: vi.fn(() => "internal-secret")
}));
vi.mock("@/src/cases/workflow-store", () => ({
  WorkflowStore: class {
    answerQuestion = answerQuestion;
  }
}));
vi.mock("@/src/db/local", () => ({ getLocalDatabase: vi.fn(() => ({})) }));
vi.mock("@/src/config/runtime", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/src/config/runtime")>();
  return {
    ...original,
    parseRuntimeConfig: vi.fn(() => original.parseRuntimeConfig({
      APP_MODE: "local",
      APP_ORIGIN: "http://127.0.0.1:3000"
    }))
  };
});

import { POST } from "@/app/api/hitl/[questionId]/route";

describe("HITL route retry", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    answerQuestion.mockResolvedValue({
      analysisRunId: "analysis-run",
      allAnswered: true,
      reviewCompleted: false
    });
  });

  it("can redispatch the same saved answer after a temporary worker failure", async () => {
    const worker = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("{}", { status: 503 }))
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    const request = () => new Request("http://127.0.0.1:3000/api/hitl/question-1", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://127.0.0.1:3000"
      },
      body: JSON.stringify({ answer: "圖說審核" })
    });
    const context = { params: Promise.resolve({ questionId: "question-1" }) };

    const failed = await POST(request(), context);
    const recovered = await POST(request(), context);

    expect(failed.status).toBe(503);
    expect(recovered.status).toBe(200);
    await expect(recovered.json()).resolves.toEqual({ saved: true, reviewState: "completed" });
    expect(answerQuestion).toHaveBeenCalledTimes(2);
    expect(worker).toHaveBeenCalledTimes(2);
  });
});
