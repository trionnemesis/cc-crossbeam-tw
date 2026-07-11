import type { Metadata } from "next";
import type { ReactNode } from "react";
import { parseRuntimeConfig } from "@/src/config/runtime";
import "./globals.css";

const title = "Crossbeam TW｜送審文件安全工作台";
const description = "協助台灣建築與室內裝修從業人員整理送審程序、文件、補正項目與法源脈絡。";

export async function generateMetadata(): Promise<Metadata> {
  const metadataBase = new URL(parseRuntimeConfig(process.env).APP_ORIGIN);

  return {
    metadataBase,
    title,
    description,
    robots: { index: false, follow: false },
    openGraph: {
      type: "website",
      locale: "zh_TW",
      title,
      description,
      images: [{ url: "/og.png", width: 1200, height: 630, alt: "Crossbeam TW 送審文件安全工作台" }]
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: ["/og.png"]
    }
  };
}

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="zh-Hant">
      <body>{children}</body>
    </html>
  );
}
