import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { WorkflowStore } from "@/src/cases/workflow-store";
import { AppStore } from "@/src/db/app-store";
import { createMemoryDatabase } from "@/src/db/local";
import {
  analysisRun,
  auditEvent,
  hitlQuestion,
  uploadRecord,
  user
} from "@/src/db/schema";

describe("case workflow store", () => {
  it("records HITL answers and reports when the run is ready", async () => {
    const database = createMemoryDatabase();
    const userId = randomUUID();
    database.db.insert(user).values({ id: userId, name: "Owner", email: "owner@example.test" }).run();
    const app = new AppStore(database);
    await app.ensurePilotWorkspace(userId);
    const [caseItem] = await app.listCases(userId);
    const uploadId = randomUUID();
    const runId = randomUUID();
    const questionId = randomUUID();
    database.db.insert(uploadRecord).values({
      id: uploadId,
      caseId: caseItem.id,
      uploaderUserId: userId,
      objectKey: `${caseItem.id}/${uploadId}`,
      expectedSize: 10,
      maxSize: 100,
      expectedMediaType: "text/plain",
      expectedSha256: "a".repeat(64),
      tokenHash: "b".repeat(64),
      tokenExpiresAt: new Date(Date.now() + 60_000),
      state: "sanitized"
    }).run();
    database.db.insert(analysisRun).values({
      id: runId,
      caseId: caseItem.id,
      uploadId,
      status: "awaiting_review",
      deterministicResultJson: JSON.stringify({ artifact_names: [], artifacts: {} })
    }).run();
    database.db.insert(hitlQuestion).values({
      id: questionId,
      caseId: caseItem.id,
      analysisRunId: runId,
      questionKey: "procedure-stage",
      prompt: "請確認程序階段"
    }).run();

    const workflow = new WorkflowStore(database);
    await expect(workflow.answerQuestion(userId, questionId, "圖說審核")).resolves.toMatchObject({
      allAnswered: true,
      reviewCompleted: false,
      analysisRunId: runId
    });
    await expect(workflow.answerQuestion(userId, questionId, "圖說審核")).resolves.toMatchObject({
      allAnswered: true,
      reviewCompleted: false,
      analysisRunId: runId
    });
    const questions = await workflow.listQuestions(userId, caseItem.id);
    expect(questions[0]).toMatchObject({ status: "answered", answer: "圖說審核" });
    const events = await workflow.listAudit(userId, caseItem.id);
    expect(events.filter((event) => event.action === "hitl.answered")).toHaveLength(1);
    database.sqlite.close();
  });

  it("returns every analysis run newest first for history selection", async () => {
    const database = createMemoryDatabase();
    const userId = randomUUID();
    database.db.insert(user).values({ id: userId, name: "Owner", email: "owner@example.test" }).run();
    const app = new AppStore(database);
    await app.ensurePilotWorkspace(userId);
    const [caseItem] = await app.listCases(userId);
    const uploadId = randomUUID();
    database.db.insert(uploadRecord).values({
      id: uploadId,
      caseId: caseItem.id,
      uploaderUserId: userId,
      objectKey: `${caseItem.id}/${uploadId}`,
      expectedSize: 10,
      maxSize: 100,
      expectedMediaType: "text/plain",
      expectedSha256: "a".repeat(64),
      tokenHash: "b".repeat(64),
      tokenExpiresAt: new Date(Date.now() + 60_000),
      state: "sanitized"
    }).run();
    const olderId = randomUUID();
    const newerId = randomUUID();
    database.db.insert(analysisRun).values([
      {
        id: olderId,
        caseId: caseItem.id,
        uploadId,
        status: "completed",
        deterministicResultJson: JSON.stringify({ artifact_names: [], artifacts: {} }),
        createdAt: new Date("2026-07-24T00:00:00Z")
      },
      {
        id: newerId,
        caseId: caseItem.id,
        uploadId,
        status: "awaiting_review",
        deterministicResultJson: JSON.stringify({ artifact_names: [], artifacts: {} }),
        createdAt: new Date("2026-07-25T00:00:00Z")
      }
    ]).run();

    const analyses = await new WorkflowStore(database).listAnalyses(userId, caseItem.id);
    expect(analyses.map((analysis) => analysis.id)).toEqual([newerId, olderId]);
    database.sqlite.close();
  });

  it("deletes the full case graph and leaves only a content-free tombstone", async () => {
    const database = createMemoryDatabase();
    const userId = randomUUID();
    database.db.insert(user).values({ id: userId, name: "Owner", email: "owner@example.test" }).run();
    const app = new AppStore(database);
    await app.ensurePilotWorkspace(userId);
    const [caseItem] = await app.listCases(userId);
    const workflow = new WorkflowStore(database);

    const result = await workflow.deleteCase(userId, caseItem.id);
    expect(result.tombstone).toBe(createHash("sha256").update(caseItem.id).digest("hex"));
    expect(await app.listCases(userId)).toEqual([]);
    const retainedEvents = database.db.select().from(auditEvent).all();
    expect(retainedEvents).toHaveLength(2);
    expect(retainedEvents.every((event) => event.caseId === null)).toBe(true);
    expect(retainedEvents.find((event) => event.action === "case.deleted")).toMatchObject({
      action: "case.deleted",
      entityType: "case_tombstone",
      caseId: null
    });
    expect(retainedEvents.every((event) => !event.metadataJson.includes(caseItem.title))).toBe(true);
    database.sqlite.close();
  });
});
