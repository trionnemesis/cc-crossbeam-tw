import { redirect } from "next/navigation";
import { LockKeyhole } from "lucide-react";
import { getAppSession } from "@/src/auth/session";
import { parseRuntimeConfig } from "@/src/config/runtime";
import { SignInButton } from "./sign-in-button";
import { sanitizeReturnTo } from "@/src/auth/redirect";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function SignInPage({ searchParams }: { searchParams: Promise<{ returnTo?: string | string[] }> }) {
  const returnTo = sanitizeReturnTo((await searchParams).returnTo);
  const session = await getAppSession();
  if (session) redirect(returnTo);
  const config = parseRuntimeConfig(process.env);

  return (
    <main className="grid min-h-screen place-items-center px-5 py-12">
      <section className="w-full max-w-lg rounded-[6px] border border-[var(--border)] bg-white p-7 shadow-[0_24px_80px_rgb(19_40_59_/_0.08)] md:p-10">
        <LockKeyhole className="text-[var(--ink)]" size={30} aria-hidden="true" />
        <p className="mt-8 text-xs tracking-[0.18em] text-[var(--muted)] uppercase">Private access</p>
        <h1 className="mt-3 text-4xl leading-tight font-light tracking-[-0.035em] text-[var(--ink)]">
          進入安全工作台
        </h1>
        <p className="mt-5 leading-7 text-[var(--muted)]">
          通訊軟體只提供一次性入口。登入後的案件、文件與結果不會回傳至 LINE 或 Slack。
        </p>
        <div className="mt-9">
          <SignInButton localMode={config.APP_MODE === "local"} returnTo={returnTo} />
        </div>
        {config.APP_MODE === "local" ? (
          <p className="mt-5 rounded-[6px] bg-[var(--canvas)] px-4 py-3 text-xs leading-5 text-[var(--muted)]">
            本機單人模式只允許 loopback 網址，production 會強制停用。
          </p>
        ) : null}
      </section>
    </main>
  );
}
