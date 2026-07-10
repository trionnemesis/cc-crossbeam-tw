import Link from "next/link";
import { requireAppSession } from "@/src/auth/session";
import { WorkflowStore } from "@/src/cases/workflow-store";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { getLocalDatabase } from "@/src/db/local";
import { ReviewQuestionForm } from "@/src/components/review-question-form";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function ReviewPage() {
  const session = await requireAppSession();
  const config = parseRuntimeConfig(process.env);
  const questions = await new WorkflowStore(getLocalDatabase(config)).listQuestions(session.user.id);
  const pending = questions.filter((question) => question.status === "pending");
  return (
    <main className="mx-auto max-w-4xl px-5 py-8 md:px-10 md:py-12">
      <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Human in the loop</p>
      <h1 className="mt-3 text-4xl font-light tracking-[-0.04em] text-[var(--ink)] md:text-5xl">人工確認</h1>
      <p className="mt-4 leading-7 text-[var(--muted)]">低信心、專業簽證與程序階段問題必須由人回答，不能由模型自行補完。</p>
      <div className="mt-8 space-y-5">
        {pending.length === 0 ? <div className="rounded-[6px] border border-[var(--border)] bg-white p-6 text-sm text-[var(--muted)]">目前沒有待確認項目。</div> : null}
        {pending.map((question) => <section key={question.id}><Link className="mb-2 inline-block text-xs text-[var(--interactive)] hover:underline" href={`/cases/${question.caseId}`}>{question.caseTitle}</Link><ReviewQuestionForm prompt={question.prompt} questionId={question.id} /></section>)}
      </div>
    </main>
  );
}
