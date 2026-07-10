export type MembershipRole = "owner" | "reviewer";

export interface CaseMembership {
  caseId: string;
  userId: string;
  role: MembershipRole;
}

export interface MembershipReader {
  findMembership(userId: string, caseId: string): Promise<CaseMembership | null>;
}

export class AuthorizationError extends Error {
  readonly code = "FORBIDDEN";

  constructor() {
    super("The requested case is unavailable");
    this.name = "AuthorizationError";
  }
}

export async function requireCaseMembership(
  memberships: MembershipReader,
  userId: string,
  caseId: string
): Promise<CaseMembership> {
  const membership = await memberships.findMembership(userId, caseId);
  if (!membership) {
    // The generic response avoids disclosing whether a case identifier exists.
    throw new AuthorizationError();
  }
  return membership;
}
