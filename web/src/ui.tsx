import { ReactNode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import Icon, { type IconName } from "./components/Icon";
import { NAV, routeFromHash } from "./nav";
import { helpFor, hrefHelp } from "./help";
import { HelpBody } from "./help/render";

// The page name already sits in the top bar as the h1, so the page header only
// carries the description and the page-level actions.
export function PageHead({ sub, actions }: { sub?: ReactNode; actions?: ReactNode }) {
  const [open, setOpen] = useState<string | null>(null);
  const page = routeFromHash(window.location.hash).page;
  const label = (id: string) => NAV.find((n) => n.id === id)?.label ?? "This page";

  // "?" opens the help for the page on screen, except while typing, so a
  // question mark in a search box stays a question mark.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "?" || e.ctrlKey || e.metaKey || e.altKey) return;
      const el = document.activeElement as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) return;
      const current = routeFromHash(window.location.hash).page;
      if (!helpFor(current)) return;
      e.preventDefault();
      setOpen(current);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="page-head">
      <div>{sub ? <p>{sub}</p> : null}</div>
      <div className="actions">
        {actions}
        {helpFor(page) ? (
          <button className="icon-btn" aria-label={`About ${label(page)}`} title="About this page (?)" onClick={() => setOpen(page)}>
            <Icon name="help" size={15} />
          </button>
        ) : null}
      </div>
      {open ? (
        <Drawer
          title={`About ${label(open)}`}
          sub="Ships with this version; no internet needed"
          onClose={() => setOpen(null)}
          footer={<a className="link-button" href={hrefHelp(open)}>Printable page</a>}
        >
          <HelpBody text={helpFor(open) ?? ""} />
        </Drawer>
      ) : null}
    </div>
  );
}

// A page's tab row. Tabs switch views inside one page, so they share the same
// permission check, breadcrumb and sidebar entry as that page.
export function PageTabs({
  tabs,
  active,
  onSelect,
}: {
  tabs: { id: string; label: string }[];
  active: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          className={`tab ${active === t.id ? "active" : ""}`}
          onClick={() => onSelect(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Card({ title, actions, children, sub }: { title?: string; actions?: ReactNode; children: ReactNode; sub?: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="card-head">
          {title ? <h2>{title}</h2> : <span />}
          {actions ? <div className="actions">{actions}</div> : null}
        </div>
      )}
      {sub ? <div className="card-sub">{sub}</div> : null}
      {children}
    </section>
  );
}

export function SaveBar({
  note,
  saveLabel = "Save settings",
  saving,
  disabled,
  extra,
  onSave,
  onDiscard,
}: {
  note?: ReactNode;
  saveLabel?: string;
  saving?: boolean;
  disabled?: boolean;
  extra?: ReactNode;
  onSave: () => void;
  onDiscard?: () => void;
}) {
  return (
    <div className="save-bar">
      <span className="dirty">{note}</span>
      <span className="actions">
        {extra}
        {onDiscard ? <button disabled={saving} onClick={onDiscard}>Discard</button> : null}
        <button className="primary" onClick={onSave} disabled={saving || disabled}>
          {saving ? "Saving…" : saveLabel}
        </button>
      </span>
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint ? <div className="hint">{hint}</div> : null}
    </div>
  );
}

export function Switch({
  label,
  help,
  checked,
  onChange,
  disabled,
}: {
  label: ReactNode;
  help?: ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="switch" style={{ marginBottom: 10 }}>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="track" aria-hidden="true" />
      <span>
        <span className="switch-label">{label}</span>
        {help ? <span className="switch-help">{help}</span> : null}
      </span>
    </label>
  );
}

export function Info({ label, children }: { label: string; children: ReactNode }) {
  const ref = useRef<HTMLDetailsElement>(null);
  return (
    <details className="info-tip" ref={ref}>
      <summary className="info-btn" aria-label={label} title={label} style={{ listStyle: "none", cursor: "pointer" }}>
        <span aria-hidden="true">i</span>
      </summary>
      <div className="info-body">{children}</div>
    </details>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function useDialogFocus(active: boolean, onClose?: () => void, onEscape?: () => boolean) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const escapeRef = useRef(onEscape);
  escapeRef.current = onEscape;
  useEffect(() => {
    if (!active || !ref.current) return;
    const previous = document.activeElement as HTMLElement | null;
    const root = ref.current;
    const first = root.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? root).focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        // A panel may own Escape for a step-back (the attack map walks back a
        // camera level) and only let the close happen at the top level.
        if (escapeRef.current?.()) {
          e.stopPropagation();
          e.preventDefault();
          return;
        }
        if (closeRef.current) {
          e.stopPropagation();
          closeRef.current();
        }
        return;
      }
      if (e.key !== "Tab") return;
      const items = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      if (items.length === 0) return;
      const firstEl = items[0];
      const lastEl = items[items.length - 1];
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [active]);
  return ref;
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  // A wider panel for a form that carries a reference card beside a field.
  wide?: boolean;
}) {
  const ref = useDialogFocus(true, onClose);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <h2>{title}</h2>
        {children}
        {footer ? <div className="modal-actions">{footer}</div> : null}
      </div>
    </div>
  );
}

export function Drawer({
  title,
  sub,
  onClose,
  children,
  footer,
  wide,
  onEscape,
}: {
  title: ReactNode;
  sub?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  // Returns true when the panel handled Escape itself (a step back) and the
  // drawer should stay open.
  onEscape?: () => boolean;
}) {
  const ref = useDialogFocus(true, onClose, onEscape);
  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);
  return (
    <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside
        className={`drawer ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Details"}
        ref={ref}
        tabIndex={-1}
      >
        <div className="drawer-head">
          <div>
            <h2>{title}</h2>
            {sub ? <p>{sub}</p> : null}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close panel">
            <Icon name="x" />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer ? <div className="drawer-foot">{footer}</div> : null}
      </aside>
    </div>
  );
}

export function Badge({ tone, children }: { tone?: "ok" | "warn" | "bad" | "info" | ""; children: ReactNode }) {
  return (
    <span className={`badge ${tone ?? ""}`}>
      {tone ? <span className="dot" aria-hidden="true" /> : null}
      {children}
    </span>
  );
}

export function Empty({
  title,
  children,
  action,
  icon = "file",
}: {
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
  icon?: IconName;
}) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true"><Icon name={icon} /></span>
      {title ? <strong>{title}</strong> : null}
      {children ? <p>{children}</p> : null}
      {action ? <div className="btn-group">{action}</div> : null}
    </div>
  );
}

export function TableWrap({ children, toolbar }: { children: ReactNode; toolbar?: ReactNode }) {
  return (
    <>
      {toolbar ? <div className="table-toolbar">{toolbar}</div> : null}
      <div className="table-wrap">{children}</div>
    </>
  );
}

export function Skeleton({ kind = "line", count = 1, width }: { kind?: "line" | "block" | "kpi"; count?: number; width?: string }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className={`skeleton ${kind} ${width ?? ""}`} />
      ))}
    </>
  );
}

export function ConfirmDialog({
  title,
  children,
  confirmLabel = "Confirm",
  tone = "danger",
  busy,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>Cancel</button>
          <button className={tone} onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      <div className="muted" style={{ fontSize: 13, lineHeight: 1.65 }}>{children}</div>
    </Modal>
  );
}

export function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtBps(n: number): string {
  return `${fmtBytes(n)}/s`;
}

// One absolute format everywhere, regardless of the browser locale.
export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fmtAgo(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  if (Number.isNaN(d)) return iso;
  const seconds = Math.floor((Date.now() - d) / 1000);
  if (seconds < 0) {
    const s = -seconds;
    if (s < 60) return `in ${s}s`;
    if (s < 3600) return `in ${Math.floor(s / 60)}m`;
    if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
    return `in ${Math.floor(s / 86400)}d`;
  }
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}


/**
 * Imperative confirmation for destructive actions outside a component's own
 * state. Renders the same accessible dialog used elsewhere and resolves once
 * the operator confirms or dismisses it.
 */
export function confirmDialog(
  message: string,
  opts: { title?: string; confirmLabel?: string; tone?: "danger" | "primary" } = {},
): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const root = createRoot(host);
    const close = (value: boolean) => {
      root.unmount();
      host.remove();
      resolve(value);
    };
    root.render(
      <ConfirmDialog
        title={opts.title ?? "Confirm action"}
        confirmLabel={opts.confirmLabel ?? "Confirm"}
        tone={opts.tone ?? "danger"}
        onClose={() => close(false)}
        onConfirm={() => close(true)}
      >
        {message}
      </ConfirmDialog>,
    );
  });
}
