import { redirect } from "next/navigation";
import { getAppSession } from "@/src/auth/session";
import { LineLinkButton } from "@/src/components/line-link-button";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function LineLinkPage({ searchParams }: { searchParams: Promise<{ linkToken?: string }> }) {
  const { linkToken } = await searchParams;
  if (!linkToken) redirect("/cases");
  const session = await getAppSession();
  if (!session) redirect(`/sign-in?returnTo=${encodeURIComponent(`/link/line?linkToken=${linkToken}`)}`);
  return <main className="grid min-h-screen place-items-center px-5"><section className="w-full max-w-lg rounded-[6px] border border-[var(--border)] bg-white p-8"><p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Account linking</p><h1 className="mt-3 text-4xl font-light text-[var(--ink)]">連結 LINE 入口</h1><p className="mt-5 mb-8 leading-7 text-[var(--muted)]">LINE 只保存入口身分與 opaque deep link；案件內容、檔案與分析結果不會傳回聊天室。</p><LineLinkButton linkToken={linkToken} /></section></main>;
}
