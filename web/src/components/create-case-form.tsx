"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Plus } from "lucide-react";

export function CreateCaseForm() {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const router = useRouter();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const response = await fetch("/api/cases", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title })
    });
    if (!response.ok) {
      setError("案件建立失敗，請確認名稱後重試。")
      setPending(false);
      return;
    }
    const item = (await response.json()) as { id: string };
    router.push(`/cases/${item.id}`);
    router.refresh();
  }

  if (!open) {
    return (
      <button className="inline-flex min-h-11 items-center justify-center gap-2 rounded-[6px] bg-[var(--ink)] px-5 py-3 text-sm text-white" onClick={() => setOpen(true)} type="button">
        <Plus aria-hidden="true" size={18} />建立案件
      </button>
    );
  }

  return (
    <form className="w-full max-w-sm rounded-[6px] border border-[var(--border)] bg-white p-4" onSubmit={submit}>
      <label className="block text-xs font-medium text-[var(--muted)]" htmlFor="case-title">案件名稱</label>
      <input
        autoFocus
        className="mt-2 min-h-11 w-full rounded-[6px] border border-[var(--border)] px-3 text-sm"
        id="case-title"
        maxLength={80}
        minLength={2}
        onChange={(event) => setTitle(event.target.value)}
        placeholder="例如：板橋室內裝修補正"
        required
        value={title}
      />
      {error ? <p className="mt-2 text-xs text-[var(--danger)]" role="alert">{error}</p> : null}
      <div className="mt-3 flex gap-2">
        <button className="min-h-11 rounded-[6px] bg-[var(--ink)] px-4 text-sm text-white disabled:opacity-50" disabled={pending} type="submit">建立</button>
        <button className="min-h-11 rounded-[6px] px-4 text-sm text-[var(--muted)]" disabled={pending} onClick={() => setOpen(false)} type="button">取消</button>
      </div>
    </form>
  );
}
