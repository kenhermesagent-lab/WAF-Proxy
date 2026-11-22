import { Component } from "react";
import type { ReactNode } from "react";

// A page that throws must not take the console with it: show the error where
// the page would be and keep the navigation usable.
export default class PageBoundary extends Component<
  { page: string; children: ReactNode },
  { error: string; page: string }
> {
  state = { error: "", page: this.props.page };

  static getDerivedStateFromError(err: unknown) {
    return { error: err instanceof Error ? err.message : String(err) };
  }

  static getDerivedStateFromProps(props: { page: string }, state: { error: string; page: string }) {
    // Navigating to another page clears a previous failure.
    if (props.page !== state.page) return { error: "", page: props.page };
    return null;
  }

  render() {
    if (this.state.error) {
      return (
        <div className="card" role="alert">
          <h2 style={{ marginTop: 0 }}>This page could not be displayed</h2>
          <p className="muted" style={{ fontSize: 13, lineHeight: 1.65 }}>
            The console hit an unexpected error while rendering this section. Nothing was changed, and the rest of
            the navigation still works.
          </p>
          <details className="mt">
            <summary className="muted" style={{ fontSize: 12, cursor: "pointer" }}>Technical details</summary>
            <pre className="mono faint" style={{ whiteSpace: "pre-wrap", marginTop: 8, fontSize: 11.5 }}>{this.state.error}</pre>
          </details>
          <div className="row mt">
            <button className="primary" onClick={() => window.location.reload()}>Reload console</button>
            <button onClick={() => window.location.hash = "#/dashboard"}>Back to dashboard</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
