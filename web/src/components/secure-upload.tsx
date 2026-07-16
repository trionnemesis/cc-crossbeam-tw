"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { FileUp, LoaderCircle, ShieldCheck } from "lucide-react";

type UploadState =
  | "idle"
  | "hashing"
  | "uploading"
  | "processing"
  | "sanitized"
  | "rejected";

interface IntentResponse {
  uploadId: string;
  uploadUrl: string;
  headers: Record<string, string>;
}

async function sha256(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function SecureUpload({ caseId }: { caseId: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [state, setState] = useState<UploadState>("idle");
  const [message, setMessage] = useState("選擇 UTF-8 TXT 文件。原始檔案不會經過 Next.js。");
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  async function poll(uploadId: string) {
    for (let attempt = 0; attempt < 90; attempt += 1) {
      const response = await fetch(`/api/uploads/${uploadId}`, { cache: "no-store" });
      if (!response.ok) throw new Error("STATUS_UNAVAILABLE");
      const payload = (await response.json()) as { state: string; errorCode?: string | null };
      if (payload.state === "sanitized") {
        setState("sanitized");
        setMessage("文件已完成掃描與遮罩，可進入人工確認。")
        router.refresh();
        return;
      }
      if (payload.state === "rejected") {
        setState("rejected");
        setMessage(`文件已拒絕：${payload.errorCode ?? "驗證未通過"}`);
        return;
      }
      setState("processing");
      setMessage("獨立 worker 正在掃描、擷取文字並進行個資遮罩。")
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
    }
    throw new Error("PROCESSING_TIMEOUT");
  }

  async function upload() {
    if (!file || state !== "idle") return;
    try {
      setState("hashing");
      setMessage("在瀏覽器內計算 checksum，不上傳檔案內容。")
      const digest = await sha256(file);
      const intentResponse = await fetch(`/api/cases/${caseId}/uploads/intent`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          displayLabel: "案件文件",
          size: file.size,
          mediaType: file.type || "application/octet-stream",
          sha256: digest
        })
      });
      if (!intentResponse.ok) throw new Error("INTENT_REJECTED");
      const intent = (await intentResponse.json()) as IntentResponse;
      setState("uploading");
      setMessage("直接上傳至 private quarantine。")
      const uploadResponse = await fetch(intent.uploadUrl, {
        method: "PUT",
        headers: intent.headers,
        body: file
      });
      if (!uploadResponse.ok) throw new Error("UPLOAD_REJECTED");
      await poll(intent.uploadId);
    } catch {
      setState("rejected");
      setMessage("安全上傳未完成。檔案未進入分析流程，請重新選擇後再試。")
    }
  }

  function reset() {
    setFile(null);
    setState("idle");
    setMessage("選擇 UTF-8 TXT 文件。原始檔案不會經過 Next.js。")
    if (inputRef.current) inputRef.current.value = "";
  }

  const busy = ["hashing", "uploading", "processing"].includes(state);

  return (
    <section aria-labelledby="secure-upload-title" className="rounded-[6px] border border-[var(--border)] bg-white p-6 md:p-8">
      <div className="flex items-start gap-4">
        <span className="grid size-11 shrink-0 place-items-center rounded-full bg-[var(--canvas)] text-[var(--ink)]">
          <ShieldCheck aria-hidden="true" size={21} />
        </span>
        <div>
          <p className="text-xs tracking-[0.16em] text-[var(--muted)] uppercase">Private quarantine</p>
          <h2 className="mt-2 text-2xl font-light text-[var(--ink)]" id="secure-upload-title">安全上傳</h2>
        </div>
      </div>

      <label className="mt-7 block rounded-[6px] border border-dashed border-[var(--accent)] bg-[var(--canvas)] p-6 text-center">
        <FileUp aria-hidden="true" className="mx-auto text-[var(--interactive)]" size={28} />
        <span className="mt-3 block text-sm font-medium text-[var(--ink)]">選擇案件文件</span>
        <span className="mt-1 block text-xs text-[var(--muted)]">最大 25 MB；目前僅開放 UTF-8 TXT</span>
        <input
          accept="text/plain,.txt"
          className="sr-only"
          disabled={busy}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setState("idle");
          }}
          ref={inputRef}
          type="file"
        />
      </label>

      {file ? <p className="mt-4 text-sm text-[var(--muted)]">已選擇：僅在本機顯示，不保存原始檔名。</p> : null}
      <p aria-live="polite" className="mt-3 min-h-6 text-sm text-[var(--muted)]">{message}</p>

      <div className="mt-5 flex flex-wrap gap-3">
        <button
          className="inline-flex min-h-11 items-center gap-2 rounded-[6px] bg-[var(--ink)] px-5 py-3 text-sm text-white disabled:opacity-45"
          disabled={!file || state !== "idle"}
          onClick={upload}
          type="button"
        >
          {busy ? <LoaderCircle className="animate-spin" size={18} /> : <FileUp size={18} />}
          開始安全上傳
        </button>
        {state === "rejected" || state === "sanitized" ? (
          <button className="min-h-11 rounded-[6px] border border-[var(--border)] px-5 py-3 text-sm" onClick={reset} type="button">選擇其他文件</button>
        ) : null}
      </div>
    </section>
  );
}
