import "server-only";

import { randomUUID } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import { z } from "zod";
import {
  AuthorizationError,
  type MembershipReader,
  type CaseMembership
} from "@/src/auth/authorization";
import type { LocalDatabase } from "@/src/db/local";
import {
  auditEvent,
  caseMembership,
  caseRecord,
  invitation,
  tenant
} from "@/src/db/schema";

export interface CaseSummary {
  id: string;
  title: string;
  jurisdiction: string;
  procedureStage: string;
  status: string;
  updatedAt: Date;
  role: "owner" | "reviewer";
}

export class AppStore implements MembershipReader {
  constructor(private readonly database: LocalDatabase) {}

  async isInvitedEmail(email: string): Promise<boolean> {
    const normalized = email.trim().toLowerCase();
    const [row] = await this.database.db
      .select({ id: invitation.id })
      .from(invitation)
      .where(and(eq(invitation.email, normalized), eq(invitation.active, true)))
      .limit(1);
    return Boolean(row);
  }

  async findMembership(userId: string, caseId: string): Promise<CaseMembership | null> {
    const [row] = await this.database.db
      .select()
      .from(caseMembership)
      .where(and(eq(caseMembership.userId, userId), eq(caseMembership.caseId, caseId)))
      .limit(1);
    return row ?? null;
  }

  async ensurePilotWorkspace(userId: string): Promise<void> {
    const existing = await this.listCases(userId);
    if (existing.length > 0) return;

    const tenantId = randomUUID();
    const caseId = randomUUID();
    const eventId = randomUUID();
    this.database.sqlite.transaction(() => {
      this.database.db.insert(tenant).values({ id: tenantId, name: "Private Pilot" }).run();
      this.database.db
        .insert(caseRecord)
        .values({
          id: caseId,
          tenantId,
          title: "第一個安全審查案件",
          jurisdiction: "ntpc",
          procedureStage: "unknown",
          status: "awaiting_upload"
        })
        .run();
      this.database.db
        .insert(caseMembership)
        .values({ caseId, userId, role: "owner" })
        .run();
      this.database.db
        .insert(auditEvent)
        .values({
          id: eventId,
          caseId,
          actorUserId: userId,
          action: "case.created",
          entityType: "case",
          entityId: caseId,
          metadataJson: JSON.stringify({ source: "local-pilot-seed" })
        })
        .run();
    })();
  }

  async listCases(userId: string): Promise<CaseSummary[]> {
    const rows = await this.database.db
      .select({
        id: caseRecord.id,
        title: caseRecord.title,
        jurisdiction: caseRecord.jurisdiction,
        procedureStage: caseRecord.procedureStage,
        status: caseRecord.status,
        updatedAt: caseRecord.updatedAt,
        role: caseMembership.role
      })
      .from(caseMembership)
      .innerJoin(caseRecord, eq(caseMembership.caseId, caseRecord.id))
      .where(eq(caseMembership.userId, userId))
      .orderBy(desc(caseRecord.updatedAt));
    return rows;
  }

  async getCase(userId: string, caseId: string): Promise<CaseSummary> {
    const [row] = await this.database.db
      .select({
        id: caseRecord.id,
        title: caseRecord.title,
        jurisdiction: caseRecord.jurisdiction,
        procedureStage: caseRecord.procedureStage,
        status: caseRecord.status,
        updatedAt: caseRecord.updatedAt,
        role: caseMembership.role
      })
      .from(caseMembership)
      .innerJoin(caseRecord, eq(caseMembership.caseId, caseRecord.id))
      .where(and(eq(caseMembership.userId, userId), eq(caseMembership.caseId, caseId)))
      .limit(1);
    if (!row) throw new AuthorizationError();
    return row;
  }

  async createCase(userId: string, rawTitle: unknown): Promise<CaseSummary> {
    const title = z.string().trim().min(2).max(80).parse(rawTitle);
    const [membership] = await this.database.db
      .select({ tenantId: caseRecord.tenantId })
      .from(caseMembership)
      .innerJoin(caseRecord, eq(caseMembership.caseId, caseRecord.id))
      .where(eq(caseMembership.userId, userId))
      .limit(1);
    if (!membership) throw new AuthorizationError();
    const caseId = randomUUID();
    const now = new Date();
    this.database.sqlite.transaction(() => {
      this.database.db.insert(caseRecord).values({
        id: caseId,
        tenantId: membership.tenantId,
        title,
        jurisdiction: "ntpc",
        procedureStage: "unknown",
        status: "awaiting_upload",
        createdAt: now,
        updatedAt: now
      }).run();
      this.database.db.insert(caseMembership).values({ caseId, userId, role: "owner" }).run();
      this.database.db.insert(auditEvent).values({
        id: randomUUID(),
        caseId,
        actorUserId: userId,
        action: "case.created",
        entityType: "case",
        entityId: caseId,
        metadataJson: "{}",
        createdAt: now
      }).run();
    })();
    return this.getCase(userId, caseId);
  }
}
