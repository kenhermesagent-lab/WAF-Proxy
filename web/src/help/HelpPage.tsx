import { useEffect } from "react";
import Icon from "../components/Icon";
import { href, NAV } from "../nav";
import { helpFor } from "./index";
import { HelpBody } from "./render";

// The printable copy of a page's help. It reuses the drawer's Markdown and
// renderer, so the two cannot drift, and drops the console chrome in print.
export default function HelpPage({ page }: { page: string }) {
  const label = NAV.find((n) => n.id === page)?.label ?? "This page";
  // The document title is what a printed copy carries in its header.
  useEffect(() => {
    const was = document.title;
    document.title = `${label} help · WAF-Proxy`;
    return () => {
      document.title = was;
    };
  }, [label]);

  return (
    <div className="help-page">
      <div className="help-page-bar">
        <a className="link-button" href={href(page)}>
          <Icon name="chevronLeft" size={14} /> Back to {label}
        </a>
        <button className="link-button" onClick={() => window.print()}>Print</button>
      </div>
      <article className="card help-print">
        <h1>{label}</h1>
        <p className="faint small-text">Page help from this WAF-Proxy install. No internet needed.</p>
        <HelpBody text={helpFor(page) ?? ""} />
      </article>
    </div>
  );
}
