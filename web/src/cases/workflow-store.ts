import "server-only";

import { createHash, randomUUID } from "node:crypto";
import { existsSync, realpathSync, unlinkSync } from "node:fs";
import path from "node:path";
import { and, asc, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { requireCaseMembership } from "@/src/auth/authorization";
import { AppStore } from "@/src/db/app-store";
import type { LocalDatabase } from "@/src/db/local";
import {
  analysisRun,
  artifact,
  auditEvent,
  caseMembership,
  caseRecord,
  hitlQuestion,
  uploadRecord
} from "@/src/db/schema";

export interface GateView {
  gate: string;
  status: string;
  reason: string;
}

export interface SourceView {
  key: string;
  lawName: string;
  article: string;
  sourceUrl: string;
  authorityRank: number | null;
  licenseStatus: string;
}

export interface CorrectionView {
  key: string;
  text: string;
  lawName: string;
  article: string;
  humanReviewRequired: boolean;
}

export interface AnalysisView {
  id: string;
  status: string;
  modelStatus: string;
  humanReviewRequired: boolean;
  artifactNames: string[];
  gates: GateView[];
  sources: SourceView[];
  corrections: CorrectionView[];
  modelSummary: string | null;
  responseDraft: string | null;
}

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function parseAnalysis(row: {
  id: string;
  status: string;
  modelStatus: string;
  deterministicResultJson: string | null;
  modelResultJson: string | null;
  responseResultJson: string | null;
}): AnalysisView {
  const deterministic = object(row.deterministicResultJson ? JSON.parse(row.deterministicResultJson) : {});
  const artifacts = object(deterministic.artifacts);
  const runMeta = object(artifacts["run_meta.json"]);
  const snapshot = object(artifacts["law_snapshot.json"]);
  const corrections = array(artifacts["atomic_correction_items.json"]);
  const model = object(row.modelResultJson ? JSON.parse(row.modelResultJson) : {});
  const response = object(row.responseResultJson ? JSON.parse(row.responseResultJson) : {});
  const responseArtifacts = object(response.artifacts);

  return {
    id: row.id,
    status: row.status,
    modelStatus: row.modelStatus,
    humanReviewRequired: Boolean(deterministic.human_review_required),
    artifactNames: array(deterministic.artifact_names).map((item) => text(item)).filter(Boolean),
    gates: array(runMeta.gates).slice(0, 20).map((item) => {
      const gate = object(item);
      return {
        gate: text(gate.gate, "unknown"),
        status: text(gate.status, "unknown"),
        reason: text(gate.reason, "未提供原因")
      };
    }),
    sources: array(snapshot.entries).slice(0, 30).map((item, index) => {
      const source = object(item);
      return {
        key: `${text(source.law_id)}-${text(source.article)}-${index}`,
        lawName: text(source.law_name, "未命名法源"),
        article: text(source.article, text(source.item, "—")),
        sourceUrl: text(source.source_url),
        authorityRank: typeof source.source_authority_rank === "number" ? source.source_authority_rank : null,
        licenseStatus: text(source.source_license_status, "unknown")
      };
    }),
    corrections: corrections.slice(0, 30).map((item, index) => {
      const correction = object(item);
      return {
        key: text(correction.item_id, `correction-${index + 1}`),
        text: text(correction.text, text(correction.source_span, "需人工確認")),
        lawName: text(correction.law_name, "法源待確認"),
        article: text(correction.article, "—"),
        humanReviewRequired: Boolean(correction.human_review_required)
      };
    }),
    modelSummary: text(model.summary) || null,
    responseDraft: text(responseArtifacts["response_draft.md"]) || null
  };
}

export class WorkflowStore {
  private readonly memberships: AppStore;

  constructor(
    private readonly database: LocalDatabase
  ) {
    this.memberships = new AppStore(database);
  }

  async latestAnalysis(userId: string, caseId: string): Promise<AnalysisView | null> {
    await requireCaseMembership(this.memberships, userId, caseId);
    const [row] = await this.database.db
      .select({
        id: analysisRun.id,
        status: analysisRun.status,
        modelStatus: analysisRun.modelStatus,
        deterministicResultJson: analysisRun.deterministicResultJson,
        modelResultJson: analysisRun.modelResultJson,
        responseResultJson: analysisRun.responseResultJson
      })
      .from(analysisRun)
      .where(eq(analysisRun.caseId, caseId))
      .orderBy(desc(analysisRun.createdAt))
      .limit(1);
    return row ? parseAnalysis(row) : null;
  }

  async listQuestions(userId: string, caseId?: string) {
    if (caseId) await requireCaseMembership(this.memberships, userId, caseId);
    const where = caseId
      ? and(eq(caseMembership.userId, userId), eq(hitlQuestion.caseId, caseId))
      : eq(caseMembership.userId, userId);
    return this.database.db
      .select({
        id: hitlQuestion.id,
        caseId: hitlQuestion.caseId,
        caseTitle: caseRecord.title,
        prompt: hitlQuestion.prompt,
        status: hitlQuestion.status,
        answer: hitlQuestion.answer,
        createdAt: hitlQuestion.createdAt
      })
      .from(hitlQuestion)
      .innerJoin(caseMembership, eq(hitlQuestion.caseId, caseMembership.caseId))
      .innerJoin(caseRecord, eq(hitlQuestion.caseId, caseRecord.id))
      .where(where)
      .orderBy(asc(hitlQuestion.createdAt));
  }

  async answerQuestion(userId: string, questionId: string, rawAnswer: unknown) {
    const answer = z.string().trim().min(1).max(2000).parse(rawAnswer);
    const [question] = await this.database.db
      .select({
        id: hitlQuestion.id,
        caseId: hitlQuestion.caseId,
        analysisRunId: hitlQuestion.analysisRunId,
        status: hitlQuestion.status,
        answer: hitlQuestion.answer
      })
      .from(hitlQuestion)
      .where(eq(hitlQuestion.id, questionId))
      .limit(1);
    if (!question) return null;
    await requireCaseMembership(this.memberships, userId, question.caseId);
    const now = new Date();
    if (question.status === "pending") {
      this.database.sqlite.transaction(() => {
        const changed = this.database.db
          .update(hitlQuestion)
          .set({ status: "answered", answer, answeredByUserId: userId, answeredAt: now })
          .where(and(eq(hitlQuestion.id, questionId), eq(hitlQuestion.status, "pending")))
          .run().changes;
        if (changed !== 1) throw new Error("QUESTION_ALREADY_RESOLVED");
        this.database.db.insert(auditEvent).values({
          id: randomUUID(),
          caseId: question.caseId,
          actorUserId: userId,
          action: "hitl.answered",
          entityType: "hitl_question",
          entityId: questionId,
          metadataJson: JSON.stringify({ answerLength: answer.length }),
          createdAt: now
        }).run();
      })();
    } else if (question.status !== "answered" || question.answer !== answer) {
      throw new Error("QUESTION_ALREADY_RESOLVED");
    }
    const [pending] = await this.database.db
      .select({ id: hitlQuestion.id })
      .from(hitlQuestion)
      .where(
        and(
          eq(hitlQuestion.analysisRunId, question.analysisRunId),
          eq(hitlQuestion.status, "pending")
        )
      )
      .limit(1);
    const [run] = await this.database.db
      .select({ status: analysisRun.status })
      .from(analysisRun)
      .where(eq(analysisRun.id, question.analysisRunId))
      .limit(1);
    return { ...question, allAnswered: !pending, reviewCompleted: run?.status === "completed" };
  }

  async listAudit(userId: string, caseId: string) {
    await requireCaseMembership(this.memberships, userId, caseId);
    return this.database.db
      .select({
        id: auditEvent.id,
        action: auditEvent.action,
        entityType: auditEvent.entityType,
        createdAt: auditEvent.createdAt
      })
      .from(auditEvent)
      .where(eq(auditEvent.caseId, caseId))
      .orderBy(desc(auditEvent.createdAt))
      .limit(50);
  }

  async deleteCase(userId: string, caseId: string) {
    const membership = await requireCaseMembership(this.memberships, userId, caseId);
    if (membership.role !== "owner") throw new Error("OWNER_REQUIRED");
    const paths = await this.database.db
      .select({ raw: uploadRecord.quarantinePath, sanitized: uploadRecord.sanitizedPath })
      .from(uploadRecord)
      .where(eq(uploadRecord.caseId, caseId));
    const artifactPaths = await this.database.db
      .select({ value: artifact.storagePath })
      .from(artifact)
      .where(eq(artifact.caseId, caseId));
    for (const candidate of [
      ...paths.flatMap((item) => [item.raw, item.sanitized]),
      ...artifactPaths.map((item) => item.value)
    ]) {
      if (candidate) this.deletePrivateRuntimeFile(candidate);
    }
    const tombstone = createHash("sha256").update(caseId).digest("hex");
    this.database.sqlite.transaction(() => {
      this.database.db.delete(auditEvent).where(eq(auditEvent.caseId, caseId)).run();
      this.database.db.delete(caseRecord).where(eq(caseRecord.id, caseId)).run();
      this.database.db.insert(auditEvent).values({
        id: randomUUID(),
        caseId: null,
        actorUserId: userId,
        action: "case.deleted",
        entityType: "case_tombstone",
        entityId: tombstone,
        metadataJson: JSON.stringify({ objectCount: paths.length }),
        createdAt: new Date()
      }).run();
    })();
    return { tombstone, deletedObjects: paths.length };
  }

  private deletePrivateRuntimeFile(candidate: string) {
    if (!existsSync(candidate)) return;
    const runtimeRoot = realpathSync(path.resolve(process.cwd(), "..", ".runtime"));
    const target = realpathSync(candidate);
    if (target === runtimeRoot || !target.startsWith(`${runtimeRoot}${path.sep}`)) {
      throw new Error("refusing to delete a path outside private runtime storage");
    }
    unlinkSync(target);
  }
}
