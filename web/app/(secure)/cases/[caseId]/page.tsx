import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, CircleCheck, Clock3, FileLock2 } from "lucide-react";
import { AuthorizationError } from "@/src/auth/authorization";
import { requireAppSession } from "@/src/auth/session";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase } from "@/src/db/local";
import { SecureUpload } from "@/src/components/secure-upload";
import { DeleteCaseButton } from "@/src/components/delete-case-button";
import { ReviewQuestionForm } from "@/src/components/review-question-form";
import { WorkflowStore } from "@/src/cases/workflow-store";
import { UploadService } from "@/src/uploads/service";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const stateLabel: Record<string, string> = {
  pending: "等待上傳",
  uploading: "上傳中",
  uploaded: "已進入 quarantine",
  scanning: "安全掃描",
  clean: "掃描完成",
  masking: "個資遮罩",
  sanitized: "已完成遮罩",
  rejected: "已拒絕"
};

export default async function CaseDetailPage({ params }: { params: Promise<{ caseId: string }> }) {
  const session = await requireAppSession();
  const { caseId } = await params;
  const config = parseRuntimeConfig(process.env);
  const database = getLocalDatabase(config);
  const store = new AppStore(database);
  let caseItem;
  try {
    caseItem = await store.getCase(session.user.id, caseId);
  } catch (error) {
    if (error instanceof AuthorizationError) notFound();
    throw error;
  }
  const uploads = await new UploadService(database, store, config).listForCase(session.user.id, caseId);
  const workflow = new WorkflowStore(database);
  const [analysis, questions, audit] = await Promise.all([
    workflow.latestAnalysis(session.user.id, caseId),
    workflow.listQuestions(session.user.id, caseId),
    workflow.listAudit(session.user.id, caseId)
  ]);
  return (
      <main className="mx-auto max-w-6xl px-5 py-8 md:px-10 md:py-12">
        <Link className="inline-flex min-h-11 items-center gap-2 text-sm text-[var(--muted)]" href="/cases"><ArrowLeft size={17} />返回案件</Link>
        <header className="mt-6 border-b border-[var(--border)] pb-8">
          <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">{caseItem.jurisdiction} · {caseItem.procedureStage}</p>
          <h1 className="mt-3 text-4xl font-light tracking-[-0.04em] text-[var(--ink)] md:text-5xl">{caseItem.title}</h1>
          <div className="mt-5 inline-flex items-center gap-2 rounded-full bg-white px-3 py-1.5 text-xs text-[var(--muted)]"><Clock3 size={14} />{caseItem.status}</div>
        </header>

        <div className="grid gap-6 py-8 lg:grid-cols-[1.08fr_0.92fr]">
          <SecureUpload caseId={caseId} />
          <section aria-labelledby="boundary-title" className="rounded-[6px] bg-[var(--ink)] p-7 text-white">
            <FileLock2 aria-hidden="true" className="text-white/70" size={27} />
            <h2 className="mt-7 text-2xl font-light" id="boundary-title">本案件資料邊界</h2>
            <ul className="mt-6 space-y-4 text-sm leading-6 text-white/70">
              <li className="flex gap-3"><CircleCheck className="mt-0.5 shrink-0" size={17} />Next.js 只核發 metadata intent</li>
              <li className="flex gap-3"><CircleCheck className="mt-0.5 shrink-0" size={17} />raw bytes 直接進入獨立 quarantine worker</li>
              <li className="flex gap-3"><CircleCheck className="mt-0.5 shrink-0" size={17} />模型只接收遮罩後必要內容</li>
            </ul>
          </section>
        </div>

        <section aria-labelledby="documents-title" className="py-4">
          <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
            <h2 className="text-xl font-light text-[var(--ink)]" id="documents-title">文件處理狀態</h2>
            <span className="text-xs text-[var(--muted)]">{uploads.length} 份</span>
          </div>
          <div className="divide-y divide-[var(--border)]">
            {uploads.length === 0 ? <p className="py-8 text-sm text-[var(--muted)]">尚未上傳文件。</p> : null}
            {uploads.map((upload) => (
              <article className="grid gap-2 py-5 md:grid-cols-[1fr_auto]" key={upload.id}>
                <div><h3 className="font-medium text-[var(--ink)]">{upload.displayLabel}</h3><p className="mt-1 text-xs text-[var(--muted)]">{upload.mediaType} · {(upload.size / 1024).toFixed(1)} KB</p></div>
                <span className="self-start rounded-full bg-white px-3 py-1 text-xs text-[var(--muted)]">{stateLabel[upload.state] ?? upload.state}</span>
              </article>
            ))}
          </div>
        </section>

        {questions.some((question) => question.status === "pending") ? (
          <section aria-labelledby="case-review-title" className="py-10">
            <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Human in the loop</p>
            <h2 className="mt-2 text-3xl font-light text-[var(--ink)]" id="case-review-title">需要你的確認</h2>
            <div className="mt-6 grid gap-4">
              {questions.filter((question) => question.status === "pending").map((question) => (
                <ReviewQuestionForm key={question.id} prompt={question.prompt} questionId={question.id} />
              ))}
            </div>
          </section>
        ) : null}

        {analysis ? (
          <section aria-labelledby="analysis-title" className="py-10">
            <div className="flex flex-col gap-3 border-b border-[var(--border)] pb-5 md:flex-row md:items-end md:justify-between">
              <div><p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Evidence-bound result</p><h2 className="mt-2 text-3xl font-light text-[var(--ink)]" id="analysis-title">分析與證據</h2></div>
              <span className="text-xs text-[var(--muted)]">Model: {analysis.modelStatus} · Run: {analysis.status}</span>
            </div>

            {analysis.modelSummary ? <div className="mt-6 rounded-[6px] bg-[var(--ink)] p-6 text-white"><p className="text-xs tracking-[0.14em] text-white/55 uppercase">Masked AI summary</p><p className="mt-3 leading-7 text-white/82">{analysis.modelSummary}</p></div> : null}

            <div className="mt-6 grid gap-5 lg:grid-cols-2">
              <article className="rounded-[6px] border border-[var(--border)] bg-white p-6">
                <h3 className="text-xl font-light text-[var(--ink)]">Audit gates</h3>
                <ul className="mt-5 space-y-3">
                  {analysis.gates.map((gate) => <li className="grid grid-cols-[1fr_auto] gap-3 border-t border-[var(--border)] pt-3 text-sm" key={gate.gate}><div><p className="font-medium text-[var(--ink)]">{gate.gate}</p><p className="mt-1 text-xs leading-5 text-[var(--muted)]">{gate.reason}</p></div><span className="text-xs text-[var(--success)]">{gate.status}</span></li>)}
                </ul>
              </article>
              <article className="rounded-[6px] border border-[var(--border)] bg-white p-6">
                <h3 className="text-xl font-light text-[var(--ink)]">法源 snapshot</h3>
                <ul className="mt-5 space-y-3">
                  {analysis.sources.map((source) => <li className="border-t border-[var(--border)] pt-3 text-sm" key={source.key}><a className="font-medium text-[var(--interactive)] underline-offset-4 hover:underline" href={source.sourceUrl} rel="noreferrer" target="_blank">{source.lawName} {source.article}</a><p className="mt-1 text-xs text-[var(--muted)]">Rank {source.authorityRank ?? "—"} · {source.licenseStatus}</p></li>)}
                </ul>
              </article>
            </div>

            <article className="mt-5 rounded-[6px] border border-[var(--border)] bg-white p-6">
              <h3 className="text-xl font-light text-[var(--ink)]">補正項目</h3>
              <div className="mt-5 divide-y divide-[var(--border)]">
                {analysis.corrections.length === 0 ? <p className="py-4 text-sm text-[var(--muted)]">目前沒有可顯示的 atomic correction item。</p> : null}
                {analysis.corrections.map((item) => <div className="py-4" key={item.key}><p className="leading-7 text-[var(--text)]">{item.text}</p><p className="mt-2 text-xs text-[var(--muted)]">{item.lawName} {item.article} · {item.humanReviewRequired ? "需人工確認" : "已具證據"}</p></div>)}
              </div>
            </article>

            {analysis.responseDraft ? <article className="mt-5 rounded-[6px] border border-[var(--border)] bg-white p-6"><h3 className="text-xl font-light text-[var(--ink)]">補正回覆草稿</h3><pre className="mt-5 overflow-x-auto whitespace-pre-wrap font-sans text-sm leading-7 text-[var(--text)]">{analysis.responseDraft}</pre></article> : null}
          </section>
        ) : null}

        <section aria-labelledby="audit-title" className="py-10">
          <h2 className="text-2xl font-light text-[var(--ink)]" id="audit-title">Audit timeline</h2>
          <ol className="mt-5 border-l border-[var(--border)] pl-5">
            {audit.map((event) => <li className="relative pb-5 text-sm" key={event.id}><span className="absolute -left-[1.45rem] top-1 size-2 rounded-full bg-[var(--accent)]" /><p className="font-medium text-[var(--ink)]">{event.action}</p><p className="mt-1 text-xs text-[var(--muted)]">{event.entityType} · {event.createdAt.toLocaleString("zh-TW")}</p></li>)}
          </ol>
        </section>

        <section aria-labelledby="delete-title" className="border-t border-[var(--border)] py-10">
          <h2 className="text-lg font-medium text-[var(--danger)]" id="delete-title">刪除與保存</h2>
          <p className="mt-2 mb-5 max-w-2xl text-sm leading-6 text-[var(--muted)]">刪除會移除 quarantine、masked artifact、analysis 與 HITL，只保留不含內容的 audit tombstone。</p>
          <DeleteCaseButton caseId={caseId} />
        </section>
      </main>
  );
}
