import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import Database from "better-sqlite3";

const webOrigin = "http://127.0.0.1:3000";
const fixturePath = path.resolve(process.cwd(), "..", "tests", "fixtures", "secure_upload_canary.txt");
const databasePath = path.resolve(process.cwd(), "..", ".runtime", "secure-web.sqlite");
const canaries = ["A123456789", "owner@example.com", "0912-345-678", "文化路一段123號"];

function cookieHeader(response: Response): string {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  const values = headers.getSetCookie?.() ?? [response.headers.get("set-cookie") ?? ""];
  return values
    .filter(Boolean)
    .map((value) => value.split(";", 1)[0])
    .join("; ");
}

async function main() {
  const signIn = await fetch(`${webOrigin}/api/auth/sign-in/anonymous`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: webOrigin },
    body: "{}"
  });
  if (!signIn.ok) throw new Error(`anonymous sign-in failed: ${signIn.status}`);
  const cookie = cookieHeader(signIn);
  if (!cookie) throw new Error("anonymous sign-in returned no session cookie");

  const casesResponse = await fetch(`${webOrigin}/cases`, { headers: { cookie } });
  if (!casesResponse.ok) throw new Error(`cases page failed: ${casesResponse.status}`);
  const casesHtml = await casesResponse.text();
  const caseId = casesHtml.match(/href="\/cases\/([a-f0-9-]{36})"/)?.[1];
  if (!caseId) throw new Error("seeded case link was not rendered");

  const secondSignIn = await fetch(`${webOrigin}/api/auth/sign-in/anonymous`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: webOrigin },
    body: "{}"
  });
  const secondCookie = cookieHeader(secondSignIn);
  if (!secondSignIn.ok || !secondCookie) throw new Error("second session setup failed");
  const foreignPage = await fetch(`${webOrigin}/cases/${caseId}`, { headers: { cookie: secondCookie } });
  const foreignIntent = await fetch(`${webOrigin}/api/cases/${caseId}/uploads/intent`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: secondCookie, origin: webOrigin },
    body: JSON.stringify({
      displayLabel: "案件文件",
      size: 1,
      mediaType: "text/plain",
      sha256: "0".repeat(64)
    })
  });
  const foreignDelete = await fetch(`${webOrigin}/api/cases/${caseId}`, {
    method: "DELETE",
    headers: { cookie: secondCookie, origin: webOrigin }
  });
  if (foreignPage.status !== 404 || foreignIntent.status !== 403 || foreignDelete.status !== 403) {
    throw new Error("case authorization boundary failed");
  }

  const raw = await readFile(fixturePath);
  const digest = createHash("sha256").update(raw).digest("hex");
  const intentResponse = await fetch(`${webOrigin}/api/cases/${caseId}/uploads/intent`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie, origin: webOrigin },
    body: JSON.stringify({
      displayLabel: "案件文件",
      size: raw.length,
      mediaType: "text/plain",
      sha256: digest
    })
  });
  if (intentResponse.status !== 201) {
    throw new Error(`upload intent failed: ${intentResponse.status}`);
  }
  const intent = (await intentResponse.json()) as {
    uploadId: string;
    uploadUrl: string;
    headers: Record<string, string>;
  };

  const uploadResponse = await fetch(intent.uploadUrl, {
    method: "PUT",
    headers: { ...intent.headers, origin: webOrigin },
    body: raw
  });
  if (uploadResponse.status !== 201) {
    throw new Error(`direct worker upload failed: ${uploadResponse.status}`);
  }

  let state = "uploaded";
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const statusResponse = await fetch(`${webOrigin}/api/uploads/${intent.uploadId}`, {
      headers: { cookie },
      cache: "no-store"
    });
    if (!statusResponse.ok) throw new Error(`upload status failed: ${statusResponse.status}`);
    const status = (await statusResponse.json()) as { state: string; errorCode?: string };
    state = status.state;
    if (state === "sanitized") break;
    if (state === "rejected") throw new Error(`worker rejected upload: ${status.errorCode}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (state !== "sanitized") throw new Error(`upload did not finish: ${state}`);

  const database = new Database(databasePath);
  const row = database
    .prepare(
      "SELECT u.sanitized_path, r.deterministic_result_json, r.model_status " +
        "FROM upload_record u JOIN analysis_run r ON r.upload_id = u.id WHERE u.id = ?"
    )
    .get(intent.uploadId) as {
      sanitized_path: string;
      deterministic_result_json: string;
      model_status: string;
    };
  const sanitized = await readFile(row.sanitized_path, "utf8");
  const inspected = `${sanitized}\n${row.deterministic_result_json}`;
  const leaked = canaries.filter((canary) => inspected.includes(canary));
  if (leaked.length > 0) throw new Error(`raw canary leaked across masking boundary: ${leaked.length}`);

  const paths = database
    .prepare("SELECT quarantine_path, sanitized_path FROM upload_record WHERE id = ?")
    .get(intent.uploadId) as { quarantine_path: string; sanitized_path: string };
  const questions = database
    .prepare("SELECT id FROM hitl_question WHERE case_id = ? AND status = 'pending' ORDER BY created_at")
    .all(caseId) as Array<{ id: string }>;
  const foreignStatus = await fetch(`${webOrigin}/api/uploads/${intent.uploadId}`, {
    headers: { cookie: secondCookie },
    cache: "no-store"
  });
  if (foreignStatus.status !== 403) throw new Error("upload status authorization boundary failed");
  if (questions[0]) {
    const foreignReview = await fetch(`${webOrigin}/api/hitl/${questions[0].id}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: secondCookie, origin: webOrigin },
      body: JSON.stringify({ answer: "不應被接受" })
    });
    if (foreignReview.status !== 403) throw new Error("HITL authorization boundary failed");
  }
  for (const question of questions) {
    const reviewResponse = await fetch(`${webOrigin}/api/hitl/${question.id}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin: webOrigin },
      body: JSON.stringify({ answer: "圖說審核；消防與材料項目交由專業人員確認。" })
    });
    if (!reviewResponse.ok) throw new Error(`HITL answer failed: ${reviewResponse.status}`);
  }
  const completed = database
    .prepare("SELECT status, response_result_json FROM analysis_run WHERE upload_id = ?")
    .get(intent.uploadId) as { status: string; response_result_json: string | null };
  if (completed.status !== "completed" || !completed.response_result_json?.includes("response_draft.md")) {
    throw new Error("review response artifacts were not completed");
  }

  const deleteResponse = await fetch(`${webOrigin}/api/cases/${caseId}`, {
    method: "DELETE",
    headers: { cookie, origin: webOrigin }
  });
  if (!deleteResponse.ok) throw new Error(`case deletion failed: ${deleteResponse.status}`);
  const remainingCase = database.prepare("SELECT count(*) AS count FROM case_record WHERE id = ?").get(caseId) as { count: number };
  const tombstone = database
    .prepare("SELECT action, metadata_json FROM audit_event WHERE action = 'case.deleted' ORDER BY created_at DESC LIMIT 1")
    .get() as { action: string; metadata_json: string } | undefined;
  database.close();
  if (remainingCase.count !== 0 || tombstone?.action !== "case.deleted") {
    throw new Error("case graph deletion or tombstone failed");
  }
  if (existsSync(paths.quarantine_path) || existsSync(paths.sanitized_path)) {
    throw new Error("private storage objects survived case deletion");
  }

  process.stdout.write(
    `${JSON.stringify({
      signIn: "passed",
      caseAuthorization: "passed",
      directWorkerUpload: "passed",
      finalState: state,
      rawCanaryLeaks: leaked.length,
      modelStatus: row.model_status,
      hitlAnswers: questions.length,
      responseDraft: "passed",
      verifiedDeletion: "passed"
    })}\n`
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown acceptance failure";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
