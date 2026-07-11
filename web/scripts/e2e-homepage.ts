import assert from "node:assert/strict";

async function main() {
  const origin = new URL(process.env.APP_ORIGIN ?? "http://127.0.0.1:3000").origin;
  const socialImageUrl = new URL("/og.png", origin).href;
  const homepageResponse = await fetch(new URL("/", origin));
  assert.equal(homepageResponse.status, 200, "homepage must return HTTP 200");

  const html = await homepageResponse.text();
  assert.match(html, /href="\/cases"/, "homepage must keep the secure workspace entry");
  assert.match(html, /不做法律判斷/, "homepage must state the legal-judgment boundary");
  assert.match(html, /不保證審查必過/, "homepage must state the approval boundary");
  assert.ok(
    html.includes(`<meta property="og:image" content="${socialImageUrl}"`),
    "homepage must render an absolute social image URL from APP_ORIGIN"
  );

  const socialImageResponse = await fetch(socialImageUrl);
  assert.equal(socialImageResponse.status, 200, "social image must return HTTP 200");
  assert.equal(socialImageResponse.headers.get("content-type"), "image/png");

  console.log(`homepage acceptance passed: ${origin}`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
