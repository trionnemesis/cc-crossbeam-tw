import { relations, sql } from "drizzle-orm";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const user = sqliteTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  image: text("image"),
  isAnonymous: integer("is_anonymous", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
});

export const session = sqliteTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
    token: text("token").notNull().unique(),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" })
  },
  (table) => [index("session_user_id_idx").on(table.userId)]
);

export const account = sqliteTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp" }),
    refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp" }),
    scope: text("scope"),
    password: text("password"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [
    uniqueIndex("account_provider_subject_idx").on(table.providerId, table.accountId),
    index("account_user_id_idx").on(table.userId)
  ]
);

export const verification = sqliteTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("verification_identifier_idx").on(table.identifier)]
);

export const tenant = sqliteTable("tenant", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
});

export const invitation = sqliteTable(
  "invitation",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenant.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    active: integer("active", { mode: "boolean" }).notNull().default(true),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [uniqueIndex("invitation_tenant_email_idx").on(table.tenantId, table.email)]
);

export const channelIdentity = sqliteTable(
  "channel_identity",
  {
    id: text("id").primaryKey(),
    channel: text("channel", { enum: ["line", "slack"] }).notNull(),
    channelUserId: text("channel_user_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    linkedAt: integer("linked_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    unlinkedAt: integer("unlinked_at", { mode: "timestamp" })
  },
  (table) => [
    uniqueIndex("channel_identity_subject_idx").on(table.channel, table.channelUserId),
    index("channel_identity_user_idx").on(table.userId)
  ]
);

export const channelLinkChallenge = sqliteTable(
  "channel_link_challenge",
  {
    id: text("id").primaryKey(),
    channel: text("channel", { enum: ["line", "slack"] }).notNull(),
    linkTokenHash: text("link_token_hash").notNull().unique(),
    nonceHash: text("nonce_hash").notNull().unique(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    state: text("state", { enum: ["authenticated", "linked", "failed", "expired"] })
      .notNull()
      .default("authenticated"),
    expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
    consumedAt: integer("consumed_at", { mode: "timestamp" }),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("channel_challenge_user_idx").on(table.userId, table.createdAt)]
);

export const caseRecord = sqliteTable(
  "case_record",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenant.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    jurisdiction: text("jurisdiction").notNull().default("ntpc"),
    procedureStage: text("procedure_stage").notNull().default("unknown"),
    status: text("status", {
      enum: [
        "draft",
        "awaiting_upload",
        "processing",
        "awaiting_review",
        "completed",
        "failed",
        "deleted"
      ]
    })
      .notNull()
      .default("awaiting_upload"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("case_tenant_idx").on(table.tenantId)]
);

export const caseMembership = sqliteTable(
  "case_membership",
  {
    caseId: text("case_id")
      .notNull()
      .references(() => caseRecord.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role", { enum: ["owner", "reviewer"] }).notNull()
  },
  (table) => [
    uniqueIndex("case_membership_subject_idx").on(table.caseId, table.userId),
    index("case_membership_user_idx").on(table.userId)
  ]
);

export const auditEvent = sqliteTable(
  "audit_event",
  {
    id: text("id").primaryKey(),
    caseId: text("case_id").references(() => caseRecord.id, { onDelete: "set null" }),
    actorUserId: text("actor_user_id").references(() => user.id, { onDelete: "set null" }),
    action: text("action").notNull(),
    entityType: text("entity_type").notNull(),
    entityId: text("entity_id").notNull(),
    metadataJson: text("metadata_json").notNull().default("{}"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("audit_case_created_idx").on(table.caseId, table.createdAt)]
);

export const uploadRecord = sqliteTable(
  "upload_record",
  {
    id: text("id").primaryKey(),
    caseId: text("case_id")
      .notNull()
      .references(() => caseRecord.id, { onDelete: "cascade" }),
    uploaderUserId: text("uploader_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "restrict" }),
    objectKey: text("object_key").notNull().unique(),
    displayLabel: text("display_label").notNull().default("案件文件"),
    expectedSize: integer("expected_size").notNull(),
    maxSize: integer("max_size").notNull(),
    expectedMediaType: text("expected_media_type").notNull(),
    expectedSha256: text("expected_sha256").notNull(),
    tokenHash: text("token_hash").notNull().unique(),
    tokenExpiresAt: integer("token_expires_at", { mode: "timestamp" }).notNull(),
    state: text("state", {
      enum: [
        "pending",
        "uploading",
        "uploaded",
        "scanning",
        "rejected",
        "clean",
        "masking",
        "sanitized",
        "deleted"
      ]
    })
      .notNull()
      .default("pending"),
    quarantinePath: text("quarantine_path"),
    sanitizedPath: text("sanitized_path"),
    errorCode: text("error_code"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    uploadedAt: integer("uploaded_at", { mode: "timestamp" })
  },
  (table) => [
    index("upload_case_created_idx").on(table.caseId, table.createdAt),
    index("upload_state_idx").on(table.state)
  ]
);

export const artifact = sqliteTable(
  "artifact",
  {
    id: text("id").primaryKey(),
    caseId: text("case_id")
      .notNull()
      .references(() => caseRecord.id, { onDelete: "cascade" }),
    uploadId: text("upload_id")
      .notNull()
      .references(() => uploadRecord.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    storagePath: text("storage_path").notNull(),
    sha256: text("sha256").notNull(),
    metadataJson: text("metadata_json").notNull().default("{}"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("artifact_case_upload_idx").on(table.caseId, table.uploadId)]
);

export const analysisRun = sqliteTable(
  "analysis_run",
  {
    id: text("id").primaryKey(),
    caseId: text("case_id")
      .notNull()
      .references(() => caseRecord.id, { onDelete: "cascade" }),
    uploadId: text("upload_id")
      .notNull()
      .references(() => uploadRecord.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["running", "awaiting_review", "completed", "failed"] })
      .notNull()
      .default("running"),
    deterministicResultJson: text("deterministic_result_json"),
    modelResultJson: text("model_result_json"),
    responseResultJson: text("response_result_json"),
    modelStatus: text("model_status").notNull().default("not_requested"),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`)
  },
  (table) => [index("analysis_case_created_idx").on(table.caseId, table.createdAt)]
);

export const hitlQuestion = sqliteTable(
  "hitl_question",
  {
    id: text("id").primaryKey(),
    caseId: text("case_id")
      .notNull()
      .references(() => caseRecord.id, { onDelete: "cascade" }),
    analysisRunId: text("analysis_run_id")
      .notNull()
      .references(() => analysisRun.id, { onDelete: "cascade" }),
    questionKey: text("question_key").notNull(),
    prompt: text("prompt").notNull(),
    status: text("status", { enum: ["pending", "answered", "dismissed"] })
      .notNull()
      .default("pending"),
    answer: text("answer"),
    answeredByUserId: text("answered_by_user_id").references(() => user.id, { onDelete: "set null" }),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(sql`(unixepoch())`),
    answeredAt: integer("answered_at", { mode: "timestamp" })
  },
  (table) => [
    uniqueIndex("hitl_run_question_idx").on(table.analysisRunId, table.questionKey),
    index("hitl_case_status_idx").on(table.caseId, table.status)
  ]
);

export const userRelations = relations(user, ({ many }) => ({
  sessions: many(session),
  accounts: many(account),
  memberships: many(caseMembership)
}));

export const sessionRelations = relations(session, ({ one }) => ({
  user: one(user, { fields: [session.userId], references: [user.id] })
}));

export const accountRelations = relations(account, ({ one }) => ({
  user: one(user, { fields: [account.userId], references: [user.id] })
}));

export const schema = {
  user,
  session,
  account,
  verification,
  tenant,
  invitation,
  channelIdentity,
  channelLinkChallenge,
  caseRecord,
  caseMembership,
  auditEvent,
  uploadRecord,
  artifact,
  analysisRun,
  hitlQuestion,
  userRelations,
  sessionRelations,
  accountRelations
};
