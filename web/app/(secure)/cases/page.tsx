import Link from "next/link";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { requireAppSession } from "@/src/auth/session";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase } from "@/src/db/local";
import { CreateCaseForm } from "@/src/components/create-case-form";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const statusLabel: Record<string, string> = {
  awaiting_upload: "等待安全上傳",
  processing: "處理中",
  awaiting_review: "等待人工確認",
  completed: "已完成",
  failed: "需處理"
};

export default async function CasesPage() {
  const session = await requireAppSession();
  const config = parseRuntimeConfig(process.env);
  const store = new AppStore(getLocalDatabase(config));
  await store.ensurePilotWorkspace(session.user.id);
  const cases = await store.listCases(session.user.id);

  return (
    <main className="mx-auto max-w-6xl px-5 py-8 md:px-10 md:py-12">
      <header className="flex flex-col gap-6 border-b border-[var(--border)] pb-8 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs tracking-[0.18em] text-[var(--muted)] uppercase">Secure workspace</p>
          <h1 className="mt-3 text-4xl font-light tracking-[-0.04em] text-[var(--ink)] md:text-5xl">案件</h1>
          <p className="mt-4 max-w-2xl leading-7 text-[var(--muted)]">從安全上傳、個資遮罩到法源證據與人工確認，所有狀態集中在同一案件。</p>
        </div>
        <CreateCaseForm />
      </header>

      <section aria-labelledby="case-list-title" className="py-8">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-sm font-medium text-[var(--ink)]" id="case-list-title">進行中的案件</h2>
          <span className="text-xs text-[var(--muted)]">{cases.length} 件</span>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {cases.map((item) => (
            <Link className="group rounded-[6px] border border-[var(--border)] bg-white p-6 transition hover:border-[var(--accent)]" href={`/cases/${item.id}`} key={item.id}>
              <div className="flex items-start justify-between gap-4">
                <span className="inline-flex items-center gap-2 rounded-full bg-[var(--canvas)] px-3 py-1 text-xs text-[var(--muted)]">
                  <ShieldCheck aria-hidden="true" size={14} />{statusLabel[item.status] ?? item.status}
                </span>
                <ArrowUpRight className="text-[var(--accent)] transition group-hover:translate-x-0.5 group-hover:-translate-y-0.5" size={19} />
              </div>
              <h3 className="mt-8 text-2xl font-light tracking-[-0.025em] text-[var(--ink)]">{item.title}</h3>
              <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-[var(--border)] pt-5 text-xs">
                <div><dt className="text-[var(--muted)]">法域</dt><dd className="mt-1 text-[var(--text)]">{item.jurisdiction.toUpperCase()}</dd></div>
                <div><dt className="text-[var(--muted)]">程序階段</dt><dd className="mt-1 text-[var(--text)]">{item.procedureStage}</dd></div>
              </dl>
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
