/**
 * Capture the Secure Web walkthrough used in the README.
 *
 * Drives the real pilot end to end — anonymous sign-in, quarantine upload of the
 * synthetic canary fixture, worker masking, then human confirmation — and writes
 * one screenshot per stage. Nothing is staged or mocked: what the images show is
 * what the running app produced.
 *
 * Playwright is intentionally not a project dependency; it is only needed to
 * refresh these images. Run it ad hoc:
 *
 *   cd web && npm install --no-save playwright
 *   npm start                                   # in another shell
 *   python3 -m worker.secure_worker.server      # in another shell
 *   npx tsx scripts/capture-demo.ts
 *
 * Only the de-identified fixture may be used here. These images are published.
 */
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { chromium, type Page } from "playwright";

const webOrigin = "http://127.0.0.1:3000";
const repoRoot = path.resolve(process.cwd(), "..");
// A synthetic correction notice, shaped like a real one so the walkthrough shows
// source-bound corrections in all three citation states rather than an empty list.
const fixturePath = path.join(repoRoot, "tests", "fixtures", "demo_correction_notice.txt");
const outputDir = path.join(repoRoot, "docs", "media");

// Raw values from the fixture. None of them may survive into a published image.
const canaries = ["王大明", "owner@example.com", "0912-345-678", "文化路一段123號"];

async function shoot(page: Page, name: string) {
  const file = path.join(outputDir, `${name}.png`);
  await page.screenshot({ path: file });
  return file;
}

/** Shoot one region so the image shows the evidence, not the page chrome. */
async function shootSection(page: Page, name: string, selector: string) {
  const file = path.join(outputDir, `${name}.png`);
  const section = page.locator(selector).first();
  await section.scrollIntoViewIfNeeded();
  await section.screenshot({ path: file });
  return file;
}

async function assertNoCanaryLeak(page: Page, stage: string) {
  const text = await page.evaluate(() => document.body.innerText);
  const leaked = canaries.filter((value) => text.includes(value));
  if (leaked.length > 0) {
    throw new Error(`raw canary visible at ${stage}: ${leaked.join(", ")}`);
  }
}

async function main() {
  await mkdir(outputDir, { recursive: true });
  // Use the browser already on the machine rather than downloading one; the ad hoc
  // playwright install may not match the preinstalled build.
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined
  });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    deviceScaleFactor: 2,
    locale: "zh-TW"
  });
  const page = await context.newPage();

  try {
    await page.goto(`${webOrigin}/sign-in`, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: /本機單人模式/ }).click();
    await page.waitForURL(/\/cases/, { timeout: 30_000 });
    await page.waitForLoadState("networkidle");

    const caseLink = page.locator('a[href^="/cases/"]').first();
    await caseLink.waitFor({ timeout: 30_000 });
    await caseLink.click();
    await page.waitForLoadState("networkidle");

    // 1. Quarantine intake: consent recorded, raw bytes never touch Next.js.
    await page.setInputFiles('input[type="file"]', fixturePath);
    await page.getByRole("checkbox").first().check();
    await page.locator("#secure-upload-title").scrollIntoViewIfNeeded();
    const shot1 = await shoot(page, "secure-web-1-quarantine-upload");

    await page.getByRole("button", { name: /開始安全上傳/ }).click();

    // 2. The worker has scanned, extracted and masked; gates, sources and the
    //    source-bound correction items are what matter here, not the page header.
    await page.getByText(/已完成掃描與遮罩/).waitFor({ timeout: 120_000 });
    await page.waitForLoadState("networkidle");
    await assertNoCanaryLeak(page, "post-masking case detail");
    const shot2 = await shootSection(
      page,
      "secure-web-2-masked-analysis",
      'section[aria-labelledby="analysis-title"]'
    );

    // 3. Human confirmation is a required output, not an exception.
    await page.goto(`${webOrigin}/review`, { waitUntil: "networkidle" });
    await assertNoCanaryLeak(page, "review queue");
    const shot3 = await shootSection(page, "secure-web-3-hitl-review", "main");

    // 4. Every question must be answered before the run completes — the response
    //    draft only exists once a human has confirmed all of them.
    const answers = [
      "本案為竣工查驗階段，已由承辦建築師確認。",
      "已確認消防安全設備文件由消防專業人員補齊，並附防火填塞施工照片。"
    ];
    const forms = page.locator("form:has(textarea)");
    let remaining = await forms.count();
    for (let index = 0; remaining > 0 && index < 10; index += 1) {
      const form = forms.first();
      // Type rather than fill: the textarea is a controlled React input, and its
      // submit button stays disabled until that component's onChange has run.
      const box = form.locator("textarea");
      await box.click();
      await box.pressSequentially(answers[index] ?? answers[answers.length - 1], { delay: 5 });
      await form.getByRole("button", { name: /保存回答/ }).click();
      // router.refresh() leaves the answered form mounted for a moment; waiting for
      // the count to drop keeps the next iteration off a stale, disabled form.
      const before = remaining;
      await page
        .waitForFunction(
          (count) => document.querySelectorAll("form textarea").length < count,
          before,
          { timeout: 30_000 }
        )
        .catch(() => undefined);
      await page.waitForLoadState("networkidle");
      remaining = await forms.count();
      if (remaining >= before) break;
    }

    await page.goto(`${webOrigin}/cases`, { waitUntil: "networkidle" });
    await caseLink.click();
    await page.waitForLoadState("networkidle");
    await assertNoCanaryLeak(page, "completed case");
    await page
      .getByRole("heading", { name: "補正回覆草稿" })
      .waitFor({ timeout: 30_000 });
    const shot4 = await shootSection(
      page,
      "secure-web-4-response-draft",
      "article:has(h3:text('補正回覆草稿'))"
    );

    console.log(
      JSON.stringify({ captured: [shot1, shot2, shot3, shot4], canaryLeaks: 0 }, null, 2)
    );

  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
