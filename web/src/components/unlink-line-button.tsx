"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function UnlinkLineButton() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  async function unlink() {
    setPending(true);
    setError(null);
    const response = await fetch("/api/channels/line", { method: "DELETE" });
    if (!response.ok) {
      setError("LINE 解除綁定失敗。")
      setPending(false);
      return;
    }
    router.refresh();
  }

  return <div><button className="min-h-11 rounded-[6px] border border-[var(--border)] px-4 text-sm text-[var(--muted)] disabled:opacity-50" disabled={pending} onClick={unlink} type="button">解除 LINE 綁定</button>{error ? <p className="mt-2 text-xs text-[var(--danger)]" role="alert">{error}</p> : null}</div>;
}
