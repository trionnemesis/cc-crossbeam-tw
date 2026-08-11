import type { RuntimeConfig } from "@/src/config/runtime";

export interface AllowlistIdentity {
  email?: string | null;
  isAnonymous?: boolean | null;
}

export interface InviteReader {
  isInvitedEmail(email: string): Promise<boolean>;
}

/**
 * Whether an identity is allowed to hold access *right now*.
 *
 * Evaluated on every protected entry point, not only when the account is created:
 * changing `OWNER_EMAIL` or deactivating an invitation has to take effect for
 * accounts and sessions that already exist, otherwise revocation is cosmetic.
 */
export async function isIdentityAllowed(
  config: RuntimeConfig,
  invites: InviteReader,
  identity: AllowlistIdentity
): Promise<boolean> {
  if (config.APP_MODE === "local" && identity.isAnonymous) return true;
  const email = identity.email?.trim().toLowerCase();
  if (!email) return false;
  if (config.APP_MODE === "single-user") {
    const owner = config.OWNER_EMAIL?.trim().toLowerCase();
    return Boolean(owner) && email === owner;
  }
  return invites.isInvitedEmail(email);
}
