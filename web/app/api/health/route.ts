import { NextResponse } from "next/server";
import { parseRuntimeConfig, safeConfigSummary } from "@/src/config/runtime";

export const dynamic = "force-dynamic";

export function GET() {
  const config = parseRuntimeConfig(process.env);
  return NextResponse.json({ status: "ok", ...safeConfigSummary(config) });
}
