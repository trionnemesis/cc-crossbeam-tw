import { describe, expect, it } from "vitest";
import {
  AuthorizationError,
  requireCaseMembership,
  type CaseMembership,
  type MembershipReader
} from "@/src/auth/authorization";

class FakeMemberships implements MembershipReader {
  constructor(private readonly items: CaseMembership[]) {}

  async findMembership(userId: string, caseId: string) {
    return this.items.find((item) => item.userId === userId && item.caseId === caseId) ?? null;
  }
}

describe("case authorization", () => {
  it("returns the exact membership for an authorized user", async () => {
    const store = new FakeMemberships([{ caseId: "case-a", userId: "user-a", role: "owner" }]);
    await expect(requireCaseMembership(store, "user-a", "case-a")).resolves.toMatchObject({
      role: "owner"
    });
  });

  it("does not disclose whether another user's case exists", async () => {
    const store = new FakeMemberships([{ caseId: "case-a", userId: "user-a", role: "owner" }]);

    await expect(requireCaseMembership(store, "user-b", "case-a")).rejects.toEqual(
      new AuthorizationError()
    );
    await expect(requireCaseMembership(store, "user-b", "missing-case")).rejects.toEqual(
      new AuthorizationError()
    );
  });
});
