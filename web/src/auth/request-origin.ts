import type { RuntimeConfig } from "@/src/config/runtime";

export function isSameOriginMutation(request: Request, config: RuntimeConfig): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(config.APP_ORIGIN).origin;
  } catch {
    return false;
  }
}
