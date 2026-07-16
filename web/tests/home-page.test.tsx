import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import HomePage from "@/app/page";

describe("public landing page", () => {
  it("keeps the secure workspace entry and professional boundaries visible", () => {
    const html = renderToStaticMarkup(<HomePage />);

    expect(html).toContain('href="/cases"');
    expect(html).toContain("不做法律判斷");
    expect(html).toContain("不保證審查必過");
    expect(html).toContain("原始檔案只進入 private quarantine");
  });
});
