// WCAG 2.x relative-luminance contrast, used to gate the palette in
// app/globals.css. Pure and deterministic so the check runs in vitest
// without a browser.

export type Rgb = readonly [number, number, number];

export function parseHex(hex: string): Rgb {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!match) throw new Error(`expected #rrggbb, got ${hex}`);
  const value = Number.parseInt(match[1], 16);
  return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

/** Composite a translucent foreground over an opaque background. */
export function blend(foreground: string, alpha: number, background: string): Rgb {
  if (alpha < 0 || alpha > 1) throw new Error(`alpha out of range: ${alpha}`);
  const fg = parseHex(foreground);
  const bg = parseHex(background);
  return [0, 1, 2].map((i) => Math.round(fg[i] * alpha + bg[i] * (1 - alpha))) as unknown as Rgb;
}

function channel(value: number): number {
  const c = value / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

export function relativeLuminance([r, g, b]: Rgb): number {
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function contrastRatio(a: Rgb | string, b: Rgb | string): number {
  const la = relativeLuminance(typeof a === "string" ? parseHex(a) : a);
  const lb = relativeLuminance(typeof b === "string" ? parseHex(b) : b);
  const [hi, lo] = la >= lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

/** WCAG 2.2 AA minimums: SC 1.4.3 (text) and SC 1.4.11 (non-text UI). */
export const AA = { text: 4.5, largeText: 3, nonText: 3 } as const;
