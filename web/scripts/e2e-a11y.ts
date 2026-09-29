/**
 * Accessibility acceptance for Secure Web (issue #25, runbook R11).
 *
 * Two gates against the running production build, both fail the run:
 *
 *   1. Keyboard — the core flow (sign in → create case → upload → answer every HITL
 *      question → open the result) is driven with Tab, Enter and Space only. The
 *      skip link must be the first Tab stop on every page the flow visits, and every
 *      Tab stop must draw a visible focus indicator.
 *   2. axe — every page route is scanned with the WCAG 2.0/2.1/2.2 A+AA rules at a
 *      desktop and a 390x844 viewport, in the states a user actually sees: signed
 *      out, empty case, HITL pending, completed. Any violation, and any result axe
 *      could not decide ("incomplete"), fails.
 *
 * Needs `npm start` and the worker running, as in the CI job. Only the synthetic
 * fixture is uploaded. The browser comes from CHROMIUM_PATH when set (a preinstalled
 * build); otherwise `npx playwright-core install chromium` must have run.
 *
 * Not covered here, and still manual: screen readers and real devices.
 */
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";

const webOrigin = "http://127.0.0.1:3000";
const fixturePath = path.resolve(process.cwd(), "..", "tests", "fixtures", "demo_correction_notice.txt");
// The same rule set as the manual baseline recorded in the runbook.
const wcagTags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const viewports = [
  { name: "desktop", width: 1280, height: 900 },
  { name: "mobile", width: 390, height: 844 }
] as const;
const maxTabStops = 60;

interface Finding {
  kind: "violation" | "incomplete";
  route: string;
  state: string;
  viewport: string;
  rule: string;
  impact: string | null;
  help: string;
  targets: string[];
}

interface TabStop {
  tag: string;
  type: string | null;
  label: string;
  isSkipLink: boolean;
  indicator: boolean;
}

const findings: Finding[] = [];
const keyboardFailures: string[] = [];
let scans = 0;
let tabStops = 0;

async function scan(page: Page, route: string, state: string) {
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(`${webOrigin}${route}`, { waitUntil: "networkidle" });
    await record(page, route, state, viewport.name);
  }
}

/** Scan the page as it is, for states that only exist after an interaction. */
async function record(page: Page, route: string, state: string, viewport: string) {
  const results = await new AxeBuilder({ page }).withTags(wcagTags).analyze();
  scans += 1;
  for (const [kind, items] of [
    ["violation", results.violations],
    ["incomplete", results.incomplete]
  ] as const) {
    for (const item of items) {
      findings.push({
        kind,
        route,
        state,
        viewport,
        rule: item.id,
        impact: item.impact ?? null,
        help: item.help,
        targets: item.nodes.map((node) => node.target.join(" "))
      });
    }
  }
}

async function activeTabStop(page: Page): Promise<TabStop | null> {
  return page.evaluate(() => {
    const element = document.activeElement as HTMLElement | null;
    if (!element || element === document.body) return null;
    // The file input is sr-only; its ring is drawn on the dropzone label.
    const ringHost = element.matches('input[type="file"]')
      ? (element.closest(".dropzone") as HTMLElement | null) ?? element
      : element;
    const style = getComputedStyle(ringHost);
    const rect = element.getBoundingClientRect();
    return {
      tag: element.tagName.toLowerCase(),
      type: element.getAttribute("type"),
      label: (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 40),
      isSkipLink: element.classList.contains("skip-link") && rect.top >= 0 && rect.bottom <= innerHeight,
      indicator: style.outlineStyle !== "none" && Number.parseFloat(style.outlineWidth) >= 2
    };
  });
}

function describeStop(stop: TabStop | null): string {
  if (!stop) return "<body>";
  return `${stop.tag}${stop.type ? `[type=${stop.type}]` : ""} "${stop.label}"`;
}

/** Press Tab until `matches` holds, checking the focus indicator at every stop. */
async function tabTo(page: Page, goal: string, matches: (stop: TabStop) => boolean): Promise<TabStop> {
  const visited: string[] = [];
  for (let press = 0; press < maxTabStops; press += 1) {
    await page.keyboard.press("Tab");
    const stop = await activeTabStop(page);
    visited.push(describeStop(stop));
    if (!stop) continue;
    tabStops += 1;
    if (!stop.indicator) keyboardFailures.push(`no visible focus indicator on ${describeStop(stop)} (${page.url()})`);
    if (matches(stop)) return stop;
  }
  throw new Error(`keyboard: could not reach ${goal} in ${maxTabStops} Tab presses; visited ${visited.join(" → ")}`);
}

/**
 * On a freshly loaded document the first Tab stop must be a visible skip link.
 * Not checked after a client-side navigation: the App Router starts focus
 * navigation inside the new segment, which already bypasses the sidebar.
 */
async function expectSkipLinkFirst(page: Page) {
  await page.keyboard.press("Tab");
  const stop = await activeTabStop(page);
  if (!stop?.isSkipLink) {
    keyboardFailures.push(`first Tab stop is ${describeStop(stop)}, not a visible skip link (${page.url()})`);
    return;
  }
  tabStops += 1;
  if (!stop.indicator) keyboardFailures.push(`skip link has no visible focus indicator (${page.url()})`);
}

async function expectSkipLinkMovesFocus(page: Page) {
  await page.keyboard.press("Enter");
  const target = await page.evaluate(() => document.activeElement?.id ?? "");
  if (target !== "main-content") keyboardFailures.push(`skip link moved focus to "${target}", not <main> (${page.url()})`);
}

const byLabel = (pattern: RegExp) => (stop: TabStop) => pattern.test(stop.label);

async function walkCoreFlow(context: BrowserContext, scanPage: Page): Promise<string> {
  const page = await context.newPage();
  await page.setViewportSize({ width: 1280, height: 900 });

  // Sign in.
  await page.goto(`${webOrigin}/sign-in`, { waitUntil: "networkidle" });
  await expectSkipLinkFirst(page);
  await expectSkipLinkMovesFocus(page);
  await tabTo(page, "the sign-in button", byLabel(/本機單人模式/));
  await Promise.all([page.waitForURL(/\/cases$/, { timeout: 30_000 }), page.keyboard.press("Enter")]);
  await page.waitForLoadState("networkidle");

  // Create a case. The form autofocuses its only field; Enter submits it.
  await expectSkipLinkFirst(page);
  await tabTo(page, "the create-case button", byLabel(/建立案件/));
  await page.keyboard.press("Enter");
  await page.locator("#case-title").waitFor();
  const autofocused = await page.evaluate(() => document.activeElement?.id);
  if (autofocused !== "case-title") keyboardFailures.push(`create-case form focused "${autofocused}", not its title field`);
  await record(page, "/cases", "create form open", "desktop");
  await page.keyboard.type("無障礙驗收案件");
  await Promise.all([page.waitForURL(/\/cases\/[a-f0-9-]{36}$/, { timeout: 30_000 }), page.keyboard.press("Enter")]);
  await page.waitForLoadState("networkidle");
  const caseRoute = new URL(page.url()).pathname;
  await scan(scanPage, caseRoute, "empty case");

  // Upload. Space on the focused file input must open the chooser; only choosing
  // the file happens outside the page, as it does for a real user. The case page
  // was reached by client-side navigation, so no skip-link-first check here.
  await tabTo(page, "the file input", (stop) => stop.type === "file");
  const [chooser] = await Promise.all([page.waitForEvent("filechooser", { timeout: 10_000 }), page.keyboard.press("Space")]);
  await chooser.setFiles(fixturePath);
  await tabTo(page, "the governance checkbox", (stop) => stop.type === "checkbox");
  await page.keyboard.press("Space");
  if (!(await page.getByRole("checkbox").first().isChecked())) keyboardFailures.push("Space did not check the governance checkbox");
  await tabTo(page, "the upload button", byLabel(/開始安全上傳/));
  await page.keyboard.press("Enter");
  await page.getByText(/已完成掃描與遮罩/).waitFor({ timeout: 120_000 });
  await page.waitForLoadState("networkidle");
  await page.locator("form textarea").first().waitFor({ timeout: 30_000 });
  await scan(scanPage, caseRoute, "HITL pending");
  await scan(scanPage, "/review", "HITL pending");

  // Answer every HITL question: type, Tab to the form's own submit, Enter.
  let remaining = await page.locator("form textarea").count();
  for (let round = 0; remaining > 0 && round < 10; round += 1) {
    await tabTo(page, "a HITL answer field", (stop) => stop.tag === "textarea");
    await page.keyboard.type("已由承辦建築師確認，消防與材料文件交由專業人員補齊。");
    await page.keyboard.press("Tab");
    const submit = await activeTabStop(page);
    if (!submit || !/保存回答/.test(submit.label)) {
      throw new Error(`keyboard: Tab after a HITL answer reached ${describeStop(submit)}, not its submit button`);
    }
    await page.keyboard.press("Enter");
    const before = remaining;
    await page.waitForFunction((count: number) => document.querySelectorAll("form textarea").length < count, before, {
      timeout: 30_000
    });
    remaining = await page.locator("form textarea").count();
  }
  if (remaining > 0) throw new Error(`keyboard: ${remaining} HITL question(s) left unanswered`);

  // Open the result from the case list by keyboard.
  await page.goto(`${webOrigin}/cases`, { waitUntil: "networkidle" });
  await expectSkipLinkFirst(page);
  await tabTo(page, "the case link", byLabel(/無障礙驗收案件/));
  await Promise.all([page.waitForURL(`${webOrigin}${caseRoute}`, { timeout: 30_000 }), page.keyboard.press("Enter")]);
  await page.getByRole("heading", { name: "補正回覆草稿" }).waitFor({ timeout: 30_000 });
  await page.close();
  return caseRoute;
}

async function main() {
  const browser: Browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
  // A broken flow step stops the walk, but the findings gathered so far are still reported.
  let flowError: string | null = null;
  try {
    // Signed out: the public page and the sign-in page (which redirects once signed in).
    const anonymous = await browser.newContext({ locale: "zh-TW" });
    const anonymousPage = await anonymous.newPage();
    await scan(anonymousPage, "/", "signed out");
    await scan(anonymousPage, "/sign-in", "signed out");
    await anonymous.close();

    const context = await browser.newContext({ locale: "zh-TW" });
    const scanPage = await context.newPage();
    const caseRoute = await walkCoreFlow(context, scanPage);

    // Signed in, after the flow: every remaining route in its completed state.
    await scan(scanPage, "/cases", "completed");
    await scan(scanPage, caseRoute, "completed");
    await scan(scanPage, "/review", "no pending questions");
    await scan(scanPage, "/sources", "signed in");
    await scan(scanPage, "/admin", "signed in");
    // The page renders for any token; the token is only checked when the button posts.
    await scan(scanPage, "/link/line?linkToken=a11y-acceptance", "signed in");
    await context.close();
  } catch (error: unknown) {
    flowError = error instanceof Error ? error.message : "unknown accessibility acceptance failure";
  } finally {
    await browser.close();
  }

  const violations = findings.filter((item) => item.kind === "violation");
  const incomplete = findings.filter((item) => item.kind === "incomplete");
  for (const item of findings) {
    process.stderr.write(
      `${item.kind}: ${item.rule} (${item.impact ?? "n/a"}) ${item.route} [${item.state}, ${item.viewport}] ${item.help}\n` +
        item.targets.map((target) => `    ${target}\n`).join("")
    );
  }
  for (const failure of keyboardFailures) process.stderr.write(`keyboard: ${failure}\n`);
  if (flowError) process.stderr.write(`${flowError}\n`);

  process.stdout.write(
    `${JSON.stringify({
      axeScans: scans,
      axeViolations: violations.length,
      axeIncomplete: incomplete.length,
      keyboardTabStops: tabStops,
      keyboardFailures: keyboardFailures.length,
      coreFlowByKeyboard: flowError ? "failed" : "passed"
    })}\n`
  );
  if (flowError || violations.length > 0 || incomplete.length > 0 || keyboardFailures.length > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown accessibility acceptance failure";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
