"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Trash2 } from "lucide-react";

export function DeleteCaseButton({ caseId }: { caseId: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  async function remove() {
    if (!window.confirm("確定刪除此案件及其 raw、masked、分析與人工確認資料？此動作無法復原。")) return;
    setPending(true);
    setError(null);
    const response = await fetch(`/api/cases/${caseId}`, { method: "DELETE" });
    if (!response.ok) {
      setError("案件刪除失敗。")
      setPending(false);
      return;
    }
    router.push("/cases");
    router.refresh();
  }

  return (
    <div>
      <button className="inline-flex min-h-11 items-center gap-2 rounded-[6px] border border-[var(--danger)] px-4 text-sm text-[var(--danger)] disabled:opacity-50" disabled={pending} onClick={remove} type="button"><Trash2 size={17} />刪除案件與資料</button>
      {error ? <p className="mt-2 text-xs text-[var(--danger)]" role="alert">{error}</p> : null}
    </div>
  );
}
