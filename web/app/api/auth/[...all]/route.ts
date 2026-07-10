import { getAuth } from "@/src/auth/server";

export const dynamic = "force-dynamic";

async function handler(request: Request) {
  return getAuth().handler(request);
}

export {
  handler as DELETE,
  handler as GET,
  handler as PATCH,
  handler as POST,
  handler as PUT
};
