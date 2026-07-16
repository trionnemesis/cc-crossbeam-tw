import "server-only";

import { chmodSync, mkdirSync, realpathSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import type { RuntimeConfig } from "@/src/config/runtime";
import { schema } from "@/src/db/schema";

const migrationSql = `
CREATE TABLE IF NOT EXISTS user (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  image TEXT,
  is_anonymous INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS session (
  id TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  ip_address TEXT,
  user_agent TEXT,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS session_user_id_idx ON session(user_id);
CREATE TABLE IF NOT EXISTS account (
  id TEXT PRIMARY KEY NOT NULL,
  account_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  access_token TEXT,
  refresh_token TEXT,
  id_token TEXT,
  access_token_expires_at INTEGER,
  refresh_token_expires_at INTEGER,
  scope TEXT,
  password TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS account_provider_subject_idx ON account(provider_id, account_id);
CREATE INDEX IF NOT EXISTS account_user_id_idx ON account(user_id);
CREATE TABLE IF NOT EXISTS verification (
  id TEXT PRIMARY KEY NOT NULL,
  identifier TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS verification_identifier_idx ON verification(identifier);
CREATE TABLE IF NOT EXISTS tenant (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS invitation (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS invitation_tenant_email_idx ON invitation(tenant_id, email);
CREATE TABLE IF NOT EXISTS channel_identity (
  id TEXT PRIMARY KEY NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('line', 'slack')),
  channel_user_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  linked_at INTEGER NOT NULL DEFAULT (unixepoch()),
  unlinked_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS channel_identity_subject_idx ON channel_identity(channel, channel_user_id);
CREATE INDEX IF NOT EXISTS channel_identity_user_idx ON channel_identity(user_id);
CREATE TABLE IF NOT EXISTS channel_link_challenge (
  id TEXT PRIMARY KEY NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('line', 'slack')),
  link_token_hash TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'authenticated',
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS channel_challenge_user_idx ON channel_link_challenge(user_id, created_at);
CREATE TABLE IF NOT EXISTS case_record (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  jurisdiction TEXT NOT NULL DEFAULT 'ntpc',
  procedure_stage TEXT NOT NULL DEFAULT 'unknown',
  status TEXT NOT NULL DEFAULT 'awaiting_upload',
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS case_tenant_idx ON case_record(tenant_id);
CREATE TABLE IF NOT EXISTS case_membership (
  case_id TEXT NOT NULL REFERENCES case_record(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('owner', 'reviewer')),
  UNIQUE(case_id, user_id)
);
CREATE INDEX IF NOT EXISTS case_membership_user_idx ON case_membership(user_id);
CREATE TABLE IF NOT EXISTS audit_event (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT REFERENCES case_record(id) ON DELETE SET NULL,
  actor_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS audit_case_created_idx ON audit_event(case_id, created_at);
CREATE TABLE IF NOT EXISTS upload_record (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT NOT NULL REFERENCES case_record(id) ON DELETE CASCADE,
  uploader_user_id TEXT NOT NULL REFERENCES user(id) ON DELETE RESTRICT,
  object_key TEXT NOT NULL UNIQUE,
  display_label TEXT NOT NULL DEFAULT '案件文件',
  expected_size INTEGER NOT NULL,
  max_size INTEGER NOT NULL,
  expected_media_type TEXT NOT NULL,
  expected_sha256 TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  quarantine_path TEXT,
  sanitized_path TEXT,
  error_code TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  uploaded_at INTEGER
);
CREATE INDEX IF NOT EXISTS upload_case_created_idx ON upload_record(case_id, created_at);
CREATE INDEX IF NOT EXISTS upload_state_idx ON upload_record(state);
CREATE TABLE IF NOT EXISTS artifact (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT NOT NULL REFERENCES case_record(id) ON DELETE CASCADE,
  upload_id TEXT NOT NULL REFERENCES upload_record(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS artifact_case_upload_idx ON artifact(case_id, upload_id);
CREATE TABLE IF NOT EXISTS analysis_run (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT NOT NULL REFERENCES case_record(id) ON DELETE CASCADE,
  upload_id TEXT NOT NULL REFERENCES upload_record(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'running',
  deterministic_result_json TEXT,
  model_result_json TEXT,
  response_result_json TEXT,
  model_status TEXT NOT NULL DEFAULT 'not_requested',
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS analysis_case_created_idx ON analysis_run(case_id, created_at);
CREATE TABLE IF NOT EXISTS hitl_question (
  id TEXT PRIMARY KEY NOT NULL,
  case_id TEXT NOT NULL REFERENCES case_record(id) ON DELETE CASCADE,
  analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id) ON DELETE CASCADE,
  question_key TEXT NOT NULL,
  prompt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  answer TEXT,
  answered_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  answered_at INTEGER,
  UNIQUE(analysis_run_id, question_key)
);
CREATE INDEX IF NOT EXISTS hitl_case_status_idx ON hitl_question(case_id, status);
PRAGMA user_version = 3;
`;

export interface LocalDatabase {
  sqlite: Database.Database;
  db: BetterSQLite3Database<typeof schema>;
}

const globalDatabase = globalThis as typeof globalThis & {
  __crossbeamLocalDatabase?: LocalDatabase;
};

export function initializeSqlite(sqlite: Database.Database): void {
  sqlite.pragma("foreign_keys = ON");
  sqlite.pragma("busy_timeout = 5000");
  sqlite.exec(migrationSql);
  const analysisColumns = sqlite
    .prepare("PRAGMA table_info(analysis_run)")
    .all() as Array<{ name: string }>;
  if (!analysisColumns.some((column) => column.name === "response_result_json")) {
    sqlite.exec("ALTER TABLE analysis_run ADD COLUMN response_result_json TEXT");
  }
}

export function createMemoryDatabase(): LocalDatabase {
  const sqlite = new Database(":memory:");
  initializeSqlite(sqlite);
  return { sqlite, db: drizzle(sqlite, { schema }) };
}

function resolvePrivateRuntimeFile(configuredPath: string): string {
  const runtimeRoot = path.resolve(/* turbopackIgnore: true */ process.cwd(), "..", ".runtime");
  mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
  chmodSync(runtimeRoot, 0o700);
  const trustedRoot = realpathSync(runtimeRoot);
  const target = path.resolve(/* turbopackIgnore: true */ process.cwd(), configuredPath);
  if (path.dirname(target) !== trustedRoot) {
    throw new Error("Local database must be a direct child of the private runtime directory");
  }
  return target;
}

export function getLocalDatabase(config: RuntimeConfig): LocalDatabase {
  if (config.APP_MODE === "production") {
    throw new Error("Local SQLite adapter is forbidden in production");
  }
  if (!globalDatabase.__crossbeamLocalDatabase) {
    const databasePath = resolvePrivateRuntimeFile(config.DATABASE_PATH);
    const sqlite = new Database(databasePath);
    sqlite.pragma("journal_mode = WAL");
    initializeSqlite(sqlite);
    globalDatabase.__crossbeamLocalDatabase = {
      sqlite,
      db: drizzle(sqlite, { schema })
    };
  }
  return globalDatabase.__crossbeamLocalDatabase;
}
