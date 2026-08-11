import "server-only";

import { eq } from "drizzle-orm";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { isIdentityAllowed } from "@/src/auth/allowlist";
import { getAuth } from "@/src/auth/server";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase, type LocalDatabase } from "@/src/db/local";
import { session as sessionTable } from "@/src/db/schema";

/**
 * Destroy every session the user holds, not just the one on this request.
 *
 * A revoked owner keeping a valid cookie is the whole failure this guards against,
 * so the cookie presented here must stop working everywhere at once.
 */
export function revokeUserSessions(database: LocalDatabase, userId: string): void {
  database.db.delete(sessionTable).where(eq(sessionTable.userId, userId)).run();
}

export async function getAppSession() {
  const current = await getAuth().api.getSession({ headers: await headers() });
  if (!current) return null;

  const config = parseRuntimeConfig(process.env);
  const database = getLocalDatabase(config);
  const allowed = await isIdentityAllowed(config, new AppStore(database), current.user);
  if (allowed) return current;

  revokeUserSessions(database, current.user.id);
  return null;
}

export async function requireAppSession() {
  const session = await getAppSession();
  if (!session) redirect("/sign-in");
  return session;
}
