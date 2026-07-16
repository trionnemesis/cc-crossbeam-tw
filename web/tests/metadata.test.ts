import { afterEach, describe, expect, it } from "vitest";
import { generateMetadata } from "@/app/layout";

describe("site metadata", () => {
  const originalAppMode = process.env.APP_MODE;
  const originalAppOrigin = process.env.APP_ORIGIN;

  afterEach(() => {
    process.env.APP_MODE = originalAppMode;
    process.env.APP_ORIGIN = originalAppOrigin;
  });

  it("resolves the social image from validated APP_ORIGIN", async () => {
    process.env.APP_MODE = "local";
    process.env.APP_ORIGIN = "http://127.0.0.1:4321";

    const metadata = await generateMetadata();

    expect(metadata.metadataBase).toEqual(new URL("http://127.0.0.1:4321"));
    expect(metadata.openGraph).toMatchObject({
      images: [{ url: "/og.png", width: 1200, height: 630 }]
    });
  });
});
