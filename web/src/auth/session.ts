import "server-only";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAuth } from "@/src/auth/server";

export async function getAppSession() {
  return getAuth().api.getSession({ headers: await headers() });
}

export async function requireAppSession() {
  const session = await getAppSession();
  if (!session) redirect("/sign-in");
  return session;
}
