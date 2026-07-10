import { requireAppSession } from "@/src/auth/session";
import { WorkflowStore, type SourceView } from "@/src/cases/workflow-store";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase } from "@/src/db/local";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function SourcesPage() {
  const session = await requireAppSession();
  const config = parseRuntimeConfig(process.env);
  const database = getLocalDatabase(config);
  const cases = await new AppStore(database).listCases(session.user.id);
  const workflow = new WorkflowStore(database);
  const analyses = await Promise.all(cases.map((item) => workflow.latestAnalysis(session.user.id, item.id)));
  const unique = new Map<string, SourceView>();
  for (const source of analyses.flatMap((analysis) => analysis?.sources ?? [])) {
    unique.set(`${source.lawName}|${source.article}|${source.sourceUrl}`, source);
  }
  return (
    <main className="mx-auto max-w-5xl px-5 py-8 md:px-10 md:py-12">
      <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Source-bound evidence</p>
      <h1 className="mt-3 text-4xl font-light tracking-[-0.04em] text-[var(--ink)] md:text-5xl">法源</h1>
      <p className="mt-4 max-w-2xl leading-7 text-[var(--muted)]">此處只顯示已進入案件 law snapshot 的法源。即時網頁搜尋不能直接作為權威依據。</p>
      <div className="mt-8 divide-y divide-[var(--border)] border-y border-[var(--border)]">
        {unique.size === 0 ? <p className="py-7 text-sm text-[var(--muted)]">完成第一份文件分析後，法源 snapshot 會顯示在這裡。</p> : null}
        {[...unique.values()].map((source) => <article className="grid gap-3 py-5 md:grid-cols-[1fr_auto]" key={`${source.lawName}-${source.article}-${source.sourceUrl}`}><div><h2 className="text-lg font-light text-[var(--ink)]">{source.lawName} {source.article}</h2><p className="mt-1 text-xs text-[var(--muted)]">Authority rank {source.authorityRank ?? "—"} · {source.licenseStatus}</p></div><a className="self-center text-sm text-[var(--interactive)] hover:underline" href={source.sourceUrl} rel="noreferrer" target="_blank">開啟官方來源</a></article>)}
      </div>
    </main>
  );
}
