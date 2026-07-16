import Link from "next/link";
import { ArrowUpRight, Check, LockKeyhole, ShieldCheck } from "lucide-react";

const audiences = ["建築師事務所", "室內裝修業者", "代辦與行政窗口"];

const workflow = [
  {
    id: "01 / ROUTE",
    title: "程序分流",
    description: "辨識案件類型、送審階段與承辦路徑，先把問題放進正確流程。",
    artifact: "case.route"
  },
  {
    id: "02 / CHECK",
    title: "送件檢核",
    description: "依程序整理文件、圖說與附件狀態，標示缺件與待確認事項。",
    artifact: "package.check"
  },
  {
    id: "03 / RESOLVE",
    title: "補正拆解",
    description: "把補正公文拆成可指派項目，保留期限、責任與回覆證據。",
    artifact: "revision.queue"
  },
  {
    id: "04 / TRACE",
    title: "法源追溯",
    description: "連結來源、日期與案件脈絡，清楚區分引用、推論與待確認。",
    artifact: "source.trace"
  }
];

const capabilities = [
  "新北市室內裝修程序與文件 packet",
  "已遮罩補正公文的逐條任務整理",
  "消防、防火區劃與材料證明 routing",
  "來源、gate 與人工確認狀態的證據鏈"
];

const privacyRules = [
  "原始檔案只進入 private quarantine",
  "模型只接收去識別後的必要內容",
  "姓名、地址、電話與原始圖說不直接進入 prompt"
];

export default function HomePage() {
  return (
    <div className="polar-console min-h-screen bg-[var(--canvas)] text-[var(--ink)]">
      <header className="border-b border-[var(--border)] bg-white/95">
        <div className="mx-auto flex h-18 max-w-[1488px] items-center justify-between px-5 md:px-8">
          <Link className="inline-flex items-center gap-2 text-sm font-semibold tracking-[-0.02em]" href="/">
            <span className="grid size-6 place-items-center rounded-lg border border-[var(--ink)] font-mono text-[10px]">CT</span>
            Crossbeam TW
          </Link>
          <div className="flex items-center gap-5 md:gap-8">
            <span className="hidden items-center gap-2 font-mono text-[11px] tracking-[0.06em] text-[var(--muted)] uppercase sm:flex">
              <span className="h-px w-5 bg-[var(--accent)]" />
              Private pilot
            </span>
            <a className="link-underline text-sm font-semibold text-[var(--muted)]" href="#workflow">工作流程</a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1488px] px-5 py-6 md:px-8 md:py-10">
        <div className="grid gap-4 lg:grid-cols-12">
          <section className="panel flex min-h-[420px] flex-col justify-between p-6 md:p-10 lg:col-span-8" aria-labelledby="hero-title">
            <div className="max-w-[840px]">
              <p className="mono-label">安全文件審查工作台 / Taiwan</p>
              <h1 id="hero-title" className="mt-6 max-w-[800px] text-[clamp(2.75rem,5vw,4.75rem)] leading-[1.04] font-semibold tracking-[-0.055em]">
                讓送審文件先變清楚，
                <br />
                再交給專業判斷
              </h1>
              <p className="mt-6 max-w-[720px] text-base leading-7 text-[var(--muted)] md:text-lg md:leading-8">
                把程序分流、送件檢核、補正拆解與法源追溯整理成可掃讀、可接手的工作脈絡，降低團隊在文件往返裡遺失判斷依據的風險。
              </p>
            </div>
            <div className="mt-8 flex flex-col items-stretch gap-3 sm:flex-row sm:items-center sm:gap-6">
              <Link className="primary-button" href="/cases">
                進入安全工作台
                <ArrowUpRight aria-hidden="true" size={16} />
              </Link>
              <a className="link-underline inline-flex min-h-12 items-center justify-center gap-2 text-sm font-semibold sm:justify-start" href="#workflow">
                了解怎麼運作
                <ArrowUpRight aria-hidden="true" size={15} />
              </a>
            </div>
          </section>

          <aside className="panel flex min-h-[420px] flex-col p-6 md:p-8 lg:col-span-4" aria-labelledby="audience-title">
            <div className="flex items-baseline justify-between gap-4 border-b border-[var(--border)] pb-6">
              <h2 id="audience-title" className="text-base font-semibold tracking-[-0.02em]">適用工作角色</h2>
              <span className="mono-label">01 / SCOPE</span>
            </div>
            <ol className="mt-4">
              {audiences.map((audience, index) => (
                <li className="grid min-h-16 grid-cols-[2.5rem_1fr] items-center border-b border-[var(--border)] text-sm text-[var(--muted)] last:border-0" key={audience}>
                  <span className="font-mono text-[11px] text-[var(--quiet)]">0{index + 1}</span>
                  {audience}
                </li>
              ))}
            </ol>
            <p className="mt-auto pt-6 text-sm leading-6 text-[var(--muted)]">
              先建立一致的文件結構與追蹤語言，讓專業人員把時間留給真正需要判斷的地方。
            </p>
          </aside>

          <section className="panel p-6 md:p-8 lg:col-span-9" id="workflow" aria-labelledby="workflow-title">
            <div className="flex items-baseline justify-between gap-4 border-b border-[var(--border)] pb-6">
              <h2 id="workflow-title" className="text-base font-semibold tracking-[-0.02em]">四階段文件工作流</h2>
              <span className="mono-label">02 / WORKFLOW</span>
            </div>
            <div className="grid md:grid-cols-2 xl:grid-cols-4">
              {workflow.map((step) => (
                <article className="min-h-64 border-b border-[var(--border)] py-6 md:border-r md:px-6 md:first:pl-0 md:nth-[2]:border-r-0 xl:border-b-0 xl:nth-[2]:border-r xl:last:border-r-0 xl:last:pr-0" key={step.id}>
                  <p className="mono-label text-[var(--quiet)]">{step.id}</p>
                  <h3 className="mt-12 text-base font-semibold tracking-[-0.02em]">{step.title}</h3>
                  <p className="mt-3 text-sm leading-6 text-[var(--muted)]">{step.description}</p>
                  <code className="mt-7 block font-mono text-[11px] text-[var(--ink)]">{step.artifact}</code>
                </article>
              ))}
            </div>
          </section>

          <aside className="flex min-h-[360px] flex-col rounded-xl border border-[#0f172a] bg-[#0f172a] p-6 text-white md:p-8 lg:col-span-3" aria-labelledby="guardrail-title">
            <p className="font-mono text-[11px] tracking-[0.08em] text-slate-400 uppercase">03 / GUARDRAIL</p>
            <ShieldCheck aria-hidden="true" className="mt-10 text-slate-300" size={24} strokeWidth={1.5} />
            <h2 id="guardrail-title" className="mt-6 text-2xl leading-8 font-semibold tracking-[-0.035em]">工具協助整理，<br />專業負責判斷。</h2>
            <ul className="mt-6">
              <li className="border-t border-slate-700 py-4 text-sm text-slate-300">不做法律判斷</li>
              <li className="border-t border-slate-700 py-4 text-sm text-slate-300">不保證審查必過</li>
              <li className="border-t border-slate-700 py-4 text-sm text-slate-300">不替代專業簽證</li>
            </ul>
          </aside>

          <section className="panel p-6 md:p-8 lg:col-span-7" aria-labelledby="capability-title">
            <div className="flex items-baseline justify-between gap-4 border-b border-[var(--border)] pb-6">
              <h2 id="capability-title" className="text-base font-semibold">日常工作可以怎麼用</h2>
              <span className="mono-label">04 / OUTPUT</span>
            </div>
            <ul className="grid gap-x-8 md:grid-cols-2">
              {capabilities.map((capability) => (
                <li className="flex min-h-20 items-center gap-3 border-b border-[var(--border)] text-sm leading-6 text-[var(--muted)]" key={capability}>
                  <Check aria-hidden="true" className="shrink-0 text-[var(--accent)]" size={16} />
                  {capability}
                </li>
              ))}
            </ul>
          </section>

          <section className="panel p-6 md:p-8 lg:col-span-5" aria-labelledby="privacy-title">
            <div className="flex items-baseline justify-between gap-4 border-b border-[var(--border)] pb-6">
              <h2 id="privacy-title" className="text-base font-semibold">資料邊界先於分析</h2>
              <LockKeyhole aria-hidden="true" className="text-[var(--muted)]" size={18} strokeWidth={1.5} />
            </div>
            <ul>
              {privacyRules.map((rule, index) => (
                <li className="grid min-h-20 grid-cols-[2.5rem_1fr] items-center border-b border-[var(--border)] text-sm leading-6 text-[var(--muted)] last:border-0" key={rule}>
                  <span className="font-mono text-[11px] text-[var(--quiet)]">0{index + 1}</span>
                  {rule}
                </li>
              ))}
            </ul>
          </section>

          <footer className="panel grid gap-4 p-5 font-mono text-[10px] tracking-[0.06em] text-[var(--muted)] uppercase sm:grid-cols-3 lg:col-span-12">
            <div><span className="text-[var(--quiet)]">System</span><span className="ml-3 text-[var(--ink)]">CROSSBEAM.TW</span></div>
            <div><span className="text-[var(--quiet)]">Region</span><span className="ml-3 text-[var(--ink)]">NEW TAIPEI / PILOT</span></div>
            <div><span className="text-[var(--quiet)]">Boundary</span><span className="ml-3 text-[var(--ink)]">HUMAN REVIEW REQUIRED</span></div>
          </footer>
        </div>
      </main>
    </div>
  );
}
