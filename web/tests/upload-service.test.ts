import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AppStore } from "@/src/db/app-store";
import { createMemoryDatabase } from "@/src/db/local";
import { uploadRecord, user } from "@/src/db/schema";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { UploadService } from "@/src/uploads/service";

describe("upload intent service", () => {
  it("issues an opaque, short-lived capability after case authorization", async () => {
    const database = createMemoryDatabase();
    const userId = randomUUID();
    database.db.insert(user).values({ id: userId, name: "Owner", email: "owner@example.test" }).run();
    const store = new AppStore(database);
    await store.ensurePilotWorkspace(userId);
    const [caseItem] = await store.listCases(userId);
    const config = parseRuntimeConfig({ APP_MODE: "local", APP_ORIGIN: "http://127.0.0.1:3000" });
    const service = new UploadService(database, store, config);
    const sha256 = createHash("sha256").update("masked fixture").digest("hex");

    const intent = await service.createIntent(userId, caseItem.id, {
      displayLabel: "補正通知",
      size: 14,
      mediaType: "text/plain",
      sha256
    });

    expect(intent.uploadUrl).toMatch(/^http:\/\/127\.0\.0\.1:8787\/upload\/[A-Za-z0-9_-]+$/);
    expect(intent.headers["x-content-sha256"]).toBe(sha256);
    expect(new Date(intent.expiresAt).getTime()).toBeGreaterThan(Date.now());
    const [stored] = database.db.select().from(uploadRecord).all();
    expect(stored.tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(intent.uploadUrl).not.toContain(stored.tokenHash);
    database.sqlite.close();
  });

  it("rejects wrong-user, oversize, and unsupported-media intents", async () => {
    const database = createMemoryDatabase();
    const ownerId = randomUUID();
    const otherId = randomUUID();
    database.db.insert(user).values([
      { id: ownerId, name: "Owner", email: "owner@example.test" },
      { id: otherId, name: "Other", email: "other@example.test" }
    ]).run();
    const store = new AppStore(database);
    await store.ensurePilotWorkspace(ownerId);
    const [caseItem] = await store.listCases(ownerId);
    const service = new UploadService(
      database,
      store,
      parseRuntimeConfig({ APP_MODE: "local", APP_ORIGIN: "http://127.0.0.1:3000" })
    );
    const base = { displayLabel: "文件", size: 10, mediaType: "text/plain", sha256: "a".repeat(64) };

    await expect(service.createIntent(otherId, caseItem.id, base)).rejects.toThrow("unavailable");
    await expect(service.createIntent(ownerId, caseItem.id, { ...base, size: 30 * 1024 * 1024 })).rejects.toThrow();
    await expect(service.createIntent(ownerId, caseItem.id, { ...base, mediaType: "text/html" })).rejects.toThrow();
    database.sqlite.close();
  });
});
