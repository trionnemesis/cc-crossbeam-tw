export function sanitizeReturnTo(value: string | string[] | undefined): string {
  const candidate = Array.isArray(value) ? value[0] : value;
  if (!candidate || candidate.length > 1000 || !candidate.startsWith("/") || candidate.startsWith("//")) {
    return "/cases";
  }
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return "/cases";
  const parsed = new URL(candidate, "http://local.invalid");
  if (parsed.origin !== "http://local.invalid") return "/cases";
  return `${parsed.pathname}${parsed.search}`;
}
