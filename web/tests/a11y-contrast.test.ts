import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AA, blend, contrastRatio } from "@/src/a11y/contrast";

// Reads the real tokens from globals.css so a palette edit that breaks
// WCAG 2.2 AA fails here instead of shipping unmeasured (issue #25).
const css = readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8");

function tokens(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`missing ${selector} block`);
  const block = css.slice(start, css.indexOf("}", start));
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6});/gi)].map((m) => [m[1], m[2]]));
}

const base = tokens(":root");
const polar = { ...base, ...tokens(".polar-console") };
const white = "#ffffff";
const lineGreen = "#06c755";
const guardrail = "#0f172a";

type Pair = [label: string, fg: string | ReturnType<typeof blend>, bg: string, min: number];

const pairs: Pair[] = [
  // Secure workspace (:root)
  ["text on canvas", base.text, base.canvas, AA.text],
  ["ink on canvas", base.ink, base.canvas, AA.text],
  ["ink on surface", base.ink, base.surface, AA.text],
  ["muted on canvas", base.muted, base.canvas, AA.text],
  ["muted on surface", base.muted, base.surface, AA.text],
  ["danger on surface", base.danger, base.surface, AA.text],
  ["danger on canvas", base.danger, base.canvas, AA.text],
  ["success on surface", base.success, base.surface, AA.text],
  ["warning on surface", base.warning, base.surface, AA.text],
  ["interactive on surface", base.interactive, base.surface, AA.text],
  ["white on ink (buttons)", white, base.ink, AA.text],
  ["white/72 on ink (sidebar nav)", blend(white, 0.72, base.ink), base.ink, AA.text],
  ["white/70 on ink (boundary list)", blend(white, 0.7, base.ink), base.ink, AA.text],
  ["white/55 on ink (sidebar account)", blend(white, 0.55, base.ink), base.ink, AA.text],
  ["ink on LINE green (link button)", base.ink, lineGreen, AA.text],
  ["field border on surface", base["field-border"], base.surface, AA.nonText],
  ["field border on canvas", base["field-border"], base.canvas, AA.nonText],
  ["dropzone border on canvas", base.accent, base.canvas, AA.nonText],
  ["focus ring on canvas", base.interactive, base.canvas, AA.nonText],
  ["focus ring on surface", base.interactive, base.surface, AA.nonText],
  ["on-dark focus ring on ink", white, base.ink, AA.nonText],
  ["skip link text", white, base.ink, AA.text],
  // Public landing page (.polar-console)
  ["polar ink on canvas", polar.ink, polar.canvas, AA.text],
  ["polar muted on canvas", polar.muted, polar.canvas, AA.text],
  ["polar muted on surface", polar.muted, polar.surface, AA.text],
  ["polar quiet on surface", polar.quiet, polar.surface, AA.text],
  ["polar quiet on canvas", polar.quiet, polar.canvas, AA.text],
  ["polar white on primary button", white, polar.accent, AA.text],
  ["polar focus ring on canvas", polar.interactive, polar.canvas, AA.nonText],
  ["polar focus ring on surface", polar.interactive, polar.surface, AA.nonText],
  ["polar check icon on guardrail", polar.accent, guardrail, AA.nonText]
];

describe("WCAG 2.2 AA palette contrast", () => {
  it("resolves every token the checks depend on", () => {
    for (const key of ["text", "ink", "canvas", "surface", "muted", "danger", "success", "warning", "interactive", "accent", "field-border"]) {
      expect(base[key], `:root --${key}`).toMatch(/^#[0-9a-f]{6}$/i);
    }
    for (const key of ["quiet", "accent", "interactive", "muted", "canvas"]) {
      expect(polar[key], `.polar-console --${key}`).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  it.each(pairs)("%s meets its AA minimum", (_label, fg, bg, min) => {
    expect(contrastRatio(fg, bg)).toBeGreaterThanOrEqual(min);
  });
});

describe("contrast math", () => {
  it("matches the WCAG reference extremes", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio("#777777", "#777777")).toBe(1);
  });

  it("rejects malformed colors loudly", () => {
    expect(() => contrastRatio("#fff", "#000000")).toThrow();
    expect(() => blend("#ffffff", 1.5, "#000000")).toThrow();
  });
});
