"use client";

import { useState } from "react";

export function LineLinkButton({ linkToken }: { linkToken: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function link() {
    setPending(true);
    setError(null);
    const response = await fetch("/api/channels/line/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ linkToken })
    });
    if (!response.ok) {
      setError("LINE 綁定連結已失效，請回到 LINE 重新取得。")
      setPending(false);
      return;
    }
    const payload = (await response.json()) as { redirectUrl: string };
    window.location.assign(payload.redirectUrl);
  }

  return <div><button className="min-h-11 rounded-[6px] bg-[#06c755] px-6 text-sm font-medium text-white disabled:opacity-50" disabled={pending} onClick={link} type="button">繼續綁定 LINE</button>{error ? <p className="mt-3 text-sm text-[var(--danger)]" role="alert">{error}</p> : null}</div>;
}
