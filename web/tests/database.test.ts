import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { AppStore } from "@/src/db/app-store";
import { createMemoryDatabase } from "@/src/db/local";
import { invitation, tenant, user } from "@/src/db/schema";

describe("application database", () => {
  it("enforces case membership at the data boundary", async () => {
    const database = createMemoryDatabase();
    const store = new AppStore(database);
    const ownerId = randomUUID();
    const otherId = randomUUID();
    database.db.insert(user).values([
      { id: ownerId, name: "Owner", email: "owner@example.test" },
      { id: otherId, name: "Other", email: "other@example.test" }
    ]).run();

    await store.ensurePilotWorkspace(ownerId);
    const [ownerCase] = await store.listCases(ownerId);
    expect(ownerCase).toBeDefined();
    await expect(store.findMembership(otherId, ownerCase.id)).resolves.toBeNull();
    expect(await store.listCases(otherId)).toEqual([]);
    database.sqlite.close();
  });

  it("normalizes and checks active invitations", async () => {
    const database = createMemoryDatabase();
    const tenantId = randomUUID();
    database.db.insert(tenant).values({ id: tenantId, name: "Test" }).run();
    database.db.insert(invitation).values({
      id: randomUUID(),
      tenantId,
      email: "owner@example.test",
      active: true
    }).run();
    const store = new AppStore(database);
    await expect(store.isInvitedEmail(" OWNER@example.test ")).resolves.toBe(true);
    await expect(store.isInvitedEmail("unknown@example.test")).resolves.toBe(false);
    database.sqlite.close();
  });
});
