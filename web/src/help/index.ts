/// <reference types="vite/client" />
// Page help is compiled into the bundle: a self-hosted console is often on a
// LAN with no internet, so a hosted docs link would be dead exactly when a new
// administrator needs it.
const files = import.meta.glob("./*.md", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

export const HELP: Record<string, string> = Object.fromEntries(
  Object.entries(files).map(([path, text]) => [path.replace(/^\.\//, "").replace(/\.md$/, ""), text]),
);

export function helpFor(page: string): string | undefined {
  return HELP[page];
}
