import "server-only";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import type { MembershipReader } from "@/src/auth/authorization";
import { requireCaseMembership } from "@/src/auth/authorization";
import type { RuntimeConfig } from "@/src/config/runtime";
import type { LocalDatabase } from "@/src/db/local";
import { uploadRecord } from "@/src/db/schema";

const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const TOKEN_TTL_MS = 10 * 60 * 1000;
const allowedMediaTypes = new Set(["text/plain"]);

export const uploadIntentInput = z.object({
  displayLabel: z.string().trim().min(1).max(80).default("案件文件"),
  size: z.number().int().positive().max(MAX_UPLOAD_BYTES),
  mediaType: z.string().refine((value) => allowedMediaTypes.has(value), "Unsupported media type"),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  governanceAccepted: z.literal(true)
});

export type UploadIntentInput = z.infer<typeof uploadIntentInput>;

export interface UploadIntent {
  uploadId: string;
  uploadUrl: string;
  expiresAt: string;
  headers: Record<string, string>;
}

export class UploadService {
  constructor(
    private readonly database: LocalDatabase,
    private readonly memberships: MembershipReader,
    private readonly config: RuntimeConfig
  ) {}

  async createIntent(userId: string, caseId: string, rawInput: unknown): Promise<UploadIntent> {
    await requireCaseMembership(this.memberships, userId, caseId);
    const input = uploadIntentInput.parse(rawInput);
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const uploadId = randomUUID();
    const consentRecordId = randomUUID();
    const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);
    const objectKey = `${caseId}/${uploadId}`;

    await this.database.db.insert(uploadRecord).values({
      id: uploadId,
      caseId,
      uploaderUserId: userId,
      objectKey,
      displayLabel: input.displayLabel,
      expectedSize: input.size,
      maxSize: MAX_UPLOAD_BYTES,
      expectedMediaType: input.mediaType,
      expectedSha256: input.sha256,
      tokenHash,
      tokenExpiresAt: expiresAt,
      dataGovernanceJson: JSON.stringify({
        consent_record_id: consentRecordId,
        collection_purpose: "case_document_correction_analysis",
        raw_file_retention_policy: "private_until_case_deletion",
        masked_file_retention_policy: "private_until_case_deletion",
        raw_file_access_scope: "isolated_worker_only",
        deletion_request_supported: true,
        audit_log_enabled: true,
        vectorization_allowed: true
      }),
      state: "pending"
    });

    if (this.config.APP_MODE === "production") {
      throw new Error("Production GCS signed URL adapter is not configured yet");
    }
    return {
      uploadId,
      uploadUrl: `${this.config.WORKER_UPLOAD_ORIGIN}/upload/${token}`,
      expiresAt: expiresAt.toISOString(),
      headers: {
        "content-type": input.mediaType,
        "x-content-sha256": input.sha256,
        "x-upload-id": uploadId
      }
    };
  }

  async listForCase(userId: string, caseId: string) {
    await requireCaseMembership(this.memberships, userId, caseId);
    return this.database.db
      .select({
        id: uploadRecord.id,
        displayLabel: uploadRecord.displayLabel,
        mediaType: uploadRecord.expectedMediaType,
        size: uploadRecord.expectedSize,
        state: uploadRecord.state,
        errorCode: uploadRecord.errorCode,
        createdAt: uploadRecord.createdAt,
        updatedAt: uploadRecord.updatedAt
      })
      .from(uploadRecord)
      .where(eq(uploadRecord.caseId, caseId))
      .orderBy(desc(uploadRecord.createdAt));
  }

  async getStatus(userId: string, uploadId: string) {
    const [upload] = await this.database.db
      .select({
        id: uploadRecord.id,
        caseId: uploadRecord.caseId,
        state: uploadRecord.state,
        errorCode: uploadRecord.errorCode,
        updatedAt: uploadRecord.updatedAt
      })
      .from(uploadRecord)
      .where(eq(uploadRecord.id, uploadId))
      .limit(1);
    if (!upload) return null;
    await requireCaseMembership(this.memberships, userId, upload.caseId);
    return upload;
  }
}
