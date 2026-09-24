import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const read = (file: string) => readFileSync(path.resolve(__dirname, "..", file), "utf8");

// Every route under web/app that renders a page (issue #25 coverage list).
const pages = [
  "app/page.tsx",
  "app/sign-in/page.tsx",
  "app/link/line/page.tsx",
  "app/(secure)/cases/page.tsx",
  "app/(secure)/cases/[caseId]/page.tsx",
  "app/(secure)/review/page.tsx",
  "app/(secure)/sources/page.tsx",
  "app/(secure)/admin/page.tsx"
];

describe("keyboard structure", () => {
  it("renders the skip link as the first element in <body>", () => {
    expect(read("app/layout.tsx")).toMatch(/<body>\s*<a className="skip-link" href="#main-content">/);
  });

  it.each(pages)("%s exposes exactly one focusable skip-link target", (file) => {
    const matches = read(file).match(/<main id="main-content" tabIndex=\{-1\}/g) ?? [];
    expect(matches).toHaveLength(1);
  });

  it("draws the upload focus ring on the dropzone, since the file input is sr-only", () => {
    expect(read("src/components/secure-upload.tsx")).toMatch(/<label className="dropzone /);
    expect(read("app/globals.css")).toMatch(/\.dropzone:has\(input:focus-visible\)/);
  });

  it("switches the focus ring to white on ink panels that contain focusable content", () => {
    expect(read("app/(secure)/layout.tsx")).toMatch(/<aside className="on-dark /);
    expect(read("app/globals.css")).toMatch(/\.on-dark :focus-visible \{\s*outline-color: #ffffff;/);
  });

  it("gives text fields a 3:1 boundary instead of the decorative border token", () => {
    expect(read("src/components/create-case-form.tsx")).toContain("border-[var(--field-border)]");
    expect(read("src/components/review-question-form.tsx")).toContain("border-[var(--field-border)]");
  });
});
