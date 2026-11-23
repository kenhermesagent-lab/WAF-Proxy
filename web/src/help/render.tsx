import type { ReactNode } from "react";

// A Markdown subset is enough for page help, and rendering it here keeps the
// console's only runtime dependencies React and React DOM.
const INLINE = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;

function inline(text: string, key: string): ReactNode[] {
  return text
    .split(INLINE)
    .filter(Boolean)
    .map((part, i) => {
      const k = `${key}-${i}`;
      if (part.startsWith("**") && part.endsWith("**")) return <strong key={k}>{part.slice(2, -2)}</strong>;
      if (part.startsWith("`") && part.endsWith("`")) return <code key={k}>{part.slice(1, -1)}</code>;
      const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(part);
      if (link) return <a key={k} href={link[2]}>{link[1]}</a>;
      return part;
    });
}

export function HelpBody({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let list: string[] = [];
  const flush = () => {
    if (list.length === 0) return;
    const items = list;
    list = [];
    blocks.push(
      <ul key={`ul-${blocks.length}`}>
        {items.map((item, i) => <li key={i}>{inline(item, `li-${blocks.length}-${i}`)}</li>)}
      </ul>,
    );
  };

  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") {
      flush();
      continue;
    }
    if (line.startsWith("- ")) {
      list.push(line.slice(2));
      continue;
    }
    flush();
    if (line.startsWith("## ")) blocks.push(<h3 key={blocks.length}>{inline(line.slice(3), `h-${blocks.length}`)}</h3>);
    else if (line.startsWith("### ")) blocks.push(<h4 key={blocks.length}>{inline(line.slice(4), `h-${blocks.length}`)}</h4>);
    else blocks.push(<p key={blocks.length}>{inline(line, `p-${blocks.length}`)}</p>);
  }
  flush();
  return <div className="help-body">{blocks}</div>;
}
