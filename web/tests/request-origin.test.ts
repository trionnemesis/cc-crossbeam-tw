import { describe, expect, it } from "vitest";
import { isSameOriginMutation } from "@/src/auth/request-origin";
import { parseRuntimeConfig } from "@/src/config/runtime";

const config = parseRuntimeConfig({
  APP_MODE: "local",
  APP_ORIGIN: "http://127.0.0.1:3000"
});

describe("state-changing request origin", () => {
  it("accepts only the configured application origin", () => {
    expect(isSameOriginMutation(new Request("http://127.0.0.1:3000/api/cases", {
      method: "POST",
      headers: { origin: "http://127.0.0.1:3000" }
    }), config)).toBe(true);
    expect(isSameOriginMutation(new Request("http://127.0.0.1:3000/api/cases", {
      method: "POST",
      headers: { origin: "https://attacker.example" }
    }), config)).toBe(false);
    expect(isSameOriginMutation(new Request("http://127.0.0.1:3000/api/cases", {
      method: "POST"
    }), config)).toBe(false);
  });
});
