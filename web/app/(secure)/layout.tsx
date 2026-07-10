import Link from "next/link";
import type { ReactNode } from "react";
import { BookOpenText, BriefcaseBusiness, CircleUserRound, ShieldCheck } from "lucide-react";
import { requireAppSession } from "@/src/auth/session";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const navigation = [
  { href: "/cases", label: "案件", icon: BriefcaseBusiness },
  { href: "/review", label: "人工確認", icon: ShieldCheck },
  { href: "/sources", label: "法源", icon: BookOpenText },
  { href: "/admin", label: "帳號", icon: CircleUserRound }
];

export default async function SecureLayout({ children }: { children: ReactNode }) {
  const session = await requireAppSession();

  return (
    <div className="min-h-screen md:grid md:grid-cols-[250px_1fr]">
      <aside className="hidden border-r border-[var(--border)] bg-[var(--ink)] p-7 text-white md:flex md:flex-col">
        <Link className="text-sm tracking-[0.16em] uppercase" href="/cases">Crossbeam TW</Link>
        <nav aria-label="主要導覽" className="mt-16 space-y-2">
          {navigation.map(({ href, label, icon: Icon }) => (
            <Link className="flex min-h-11 items-center gap-3 rounded-[6px] px-3 text-sm text-white/72 hover:bg-white/10 hover:text-white" href={href} key={href}>
              <Icon aria-hidden="true" size={18} />{label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto border-t border-white/15 pt-5 text-xs leading-5 text-white/55">
          <p>{session.user.name}</p>
          <p className="truncate">{session.user.email}</p>
        </div>
      </aside>
      <div className="min-w-0 pb-20 md:pb-0">{children}</div>
      <nav aria-label="行動版主要導覽" className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-4 border-t border-[var(--border)] bg-white md:hidden">
        {navigation.map(({ href, label, icon: Icon }) => (
          <Link className="flex min-h-16 flex-col items-center justify-center gap-1 text-[11px] text-[var(--muted)]" href={href} key={href}>
            <Icon aria-hidden="true" size={19} />{label}
          </Link>
        ))}
      </nav>
    </div>
  );
}
