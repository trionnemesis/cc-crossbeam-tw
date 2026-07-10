import { requireAppSession } from "@/src/auth/session";
import { parseRuntimeConfig, safeConfigSummary } from "@/src/config/runtime";
import { LineLinkService } from "@/src/channels/line";
import { getLocalDatabase } from "@/src/db/local";
import { UnlinkLineButton } from "@/src/components/unlink-line-button";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function AdminPage() {
  const session = await requireAppSession();
  const config = parseRuntimeConfig(process.env);
  const summary = safeConfigSummary(config);
  const lineLinked = await new LineLinkService(getLocalDatabase(config)).isLinked(session.user.id);
  return (
    <main className="mx-auto max-w-4xl px-5 py-8 md:px-10 md:py-12">
      <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Privacy and account</p>
      <h1 className="mt-3 text-4xl font-light tracking-[-0.04em] text-[var(--ink)] md:text-5xl">帳號與資料</h1>
      <div className="mt-8 grid gap-5 md:grid-cols-2">
        <section className="rounded-[6px] border border-[var(--border)] bg-white p-6"><h2 className="text-xl font-light text-[var(--ink)]">目前登入</h2><dl className="mt-5 space-y-3 text-sm"><div><dt className="text-xs text-[var(--muted)]">名稱</dt><dd className="mt-1">{session.user.name}</dd></div><div><dt className="text-xs text-[var(--muted)]">Email</dt><dd className="mt-1 break-all">{session.user.email}</dd></div></dl></section>
        <section className="rounded-[6px] border border-[var(--border)] bg-white p-6"><h2 className="text-xl font-light text-[var(--ink)]">Runtime boundary</h2><dl className="mt-5 space-y-3 text-sm"><div><dt className="text-xs text-[var(--muted)]">Mode</dt><dd className="mt-1">{summary.mode}</dd></div><div><dt className="text-xs text-[var(--muted)]">Database / Storage</dt><dd className="mt-1">{summary.database} / {summary.storage}</dd></div><div><dt className="text-xs text-[var(--muted)]">Codex worker</dt><dd className="mt-1">{summary.codexWorkerEnabled ? "enabled" : "disabled"}</dd></div></dl></section>
      </div>
      <section className="mt-5 rounded-[6px] bg-[var(--ink)] p-6 text-white"><h2 className="text-xl font-light">保存與刪除原則</h2><ul className="mt-5 space-y-3 text-sm leading-6 text-white/72"><li>Raw 與 masked artifact 只保存在 private runtime/storage。</li><li>案件刪除會移除所有內容，只保留不含文件內容的 audit tombstone。</li><li>Production 不允許 local auth、local storage 或 Codex CLI provider。</li></ul></section>
      <section className="mt-5 rounded-[6px] border border-[var(--border)] bg-white p-6"><h2 className="text-xl font-light text-[var(--ink)]">通訊入口</h2><p className="mt-3 mb-5 text-sm text-[var(--muted)]">LINE：{lineLinked ? "已綁定" : "未綁定"}。聊天室只保留入口身分，不保存案件內容。</p>{lineLinked ? <UnlinkLineButton /> : null}</section>
    </main>
  );
}
