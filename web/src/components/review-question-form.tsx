"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function ReviewQuestionForm({ questionId, prompt }: { questionId: string; prompt: string }) {
  const [answer, setAnswer] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const response = await fetch(`/api/hitl/${questionId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ answer })
    });
    if (!response.ok) {
      setError("回答未保存，請重新嘗試。")
      setPending(false);
      return;
    }
    router.refresh();
  }

  return (
    <form className="rounded-[6px] border border-[var(--border)] bg-white p-5" onSubmit={submit}>
      <label className="block text-sm leading-6 text-[var(--ink)]" htmlFor={`answer-${questionId}`}>{prompt}</label>
      <textarea
        className="mt-4 min-h-28 w-full rounded-[6px] border border-[var(--border)] p-3 text-sm"
        id={`answer-${questionId}`}
        maxLength={2000}
        onChange={(event) => setAnswer(event.target.value)}
        required
        value={answer}
      />
      {error ? <p className="mt-2 text-xs text-[var(--danger)]" role="alert">{error}</p> : null}
      <button className="mt-3 min-h-11 rounded-[6px] bg-[var(--ink)] px-5 text-sm text-white disabled:opacity-50" disabled={pending || !answer.trim()} type="submit">保存回答</button>
    </form>
  );
}
