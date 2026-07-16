"use client";

import { useState } from "react";
import { ArrowRight, LoaderCircle } from "lucide-react";
import { authClient } from "@/src/auth/client";

export function SignInButton({ localMode, returnTo }: { localMode: boolean; returnTo: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signIn() {
    setPending(true);
    setError(null);
    const result = localMode
      ? await authClient.signIn.anonymous()
      : await authClient.signIn.social({ provider: "google", callbackURL: returnTo });
    if (result.error) {
      setError("登入失敗，請重新嘗試。")
      setPending(false);
      return;
    }
    window.location.assign(returnTo);
  }

  return (
    <div>
      <button
        className="inline-flex min-h-11 w-full items-center justify-center gap-3 rounded-[6px] bg-[var(--ink)] px-6 py-3 text-white transition hover:bg-[#1d3a52] disabled:cursor-wait disabled:opacity-60"
        disabled={pending}
        onClick={signIn}
        type="button"
      >
        {pending ? <LoaderCircle className="animate-spin" size={18} /> : <ArrowRight size={18} />}
        {localMode ? "以本機單人模式進入" : "使用 Google 登入"}
      </button>
      {error ? <p className="mt-4 text-sm text-[var(--danger)]" role="alert">{error}</p> : null}
    </div>
  );
}
