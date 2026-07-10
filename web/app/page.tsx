import Link from "next/link";
import { ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react";

const pillars = [
  "原始檔案只進入 private quarantine",
  "模型只接收去識別後的必要內容",
  "每項結論保留法源、gate 與人工確認狀態"
];

export default function HomePage() {
  return (
    <main className="min-h-screen bg-[var(--ink)] text-white">
      <section className="mx-auto flex min-h-screen max-w-[1480px] flex-col px-6 py-8 md:px-12 md:py-10">
        <header className="flex items-center justify-between border-b border-white/20 pb-6">
          <div className="flex items-center gap-3 text-sm tracking-[0.18em] uppercase">
            <ShieldCheck aria-hidden="true" size={22} />
            Crossbeam TW
          </div>
          <span className="rounded-full border border-white/30 px-4 py-2 text-xs tracking-[0.12em]">
            PRIVATE PILOT
          </span>
        </header>

        <div className="grid flex-1 items-center gap-14 py-16 lg:grid-cols-[1.25fr_0.75fr]">
          <div>
            <p className="mb-6 text-sm tracking-[0.2em] text-white/65 uppercase">
              Secure document review
            </p>
            <h1 className="max-w-4xl text-5xl leading-[1.02] font-light tracking-[-0.045em] md:text-7xl lg:text-[6.4rem]">
              安靜、清楚、
              <br />
              可追溯的補正流程
            </h1>
            <p className="mt-10 max-w-2xl text-lg leading-8 text-white/72 md:text-xl">
              為室內裝修案件建立安全上傳、個資遮罩、人工確認與法源證據鏈。
              通訊軟體只負責入口，不承載客戶文件。
            </p>
            <Link
              className="mt-10 inline-flex min-h-11 items-center gap-3 rounded-[6px] bg-white px-6 py-3 font-medium text-[var(--ink)] transition hover:bg-white/90"
              href="/cases"
            >
              進入安全工作台
              <ArrowRight aria-hidden="true" size={18} />
            </Link>
          </div>

          <aside className="rounded-[6px] border border-white/18 bg-white/[0.06] p-7 backdrop-blur md:p-9">
            <LockKeyhole aria-hidden="true" className="mb-8 text-white/75" size={30} />
            <h2 className="text-2xl font-light">資料邊界先於分析</h2>
            <ul className="mt-8 space-y-6 text-sm leading-6 text-white/72">
              {pillars.map((pillar, index) => (
                <li className="grid grid-cols-[2rem_1fr] gap-3 border-t border-white/15 pt-5" key={pillar}>
                  <span className="text-white/40">0{index + 1}</span>
                  <span>{pillar}</span>
                </li>
              ))}
            </ul>
          </aside>
        </div>
      </section>
    </main>
  );
}
