import { describe, expect, it } from "vitest";
import { securityHeaders } from "@/next.config";

describe("security headers", () => {
  it("denies framing and enables CSP, HSTS, MIME, and referrer protections", () => {
    const headers = new Map(securityHeaders.map((header) => [header.key, header.value]));
    expect(headers.get("X-Frame-Options")).toBe("DENY");
    expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headers.get("Strict-Transport-Security")).toContain("max-age=31536000");
    expect(headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("Content-Security-Policy")).toContain("object-src 'none'");
    expect(headers.get("Content-Security-Policy")).toContain("http://127.0.0.1:8787");
  });
});
