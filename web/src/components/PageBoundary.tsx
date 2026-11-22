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
        <div className="card">
          <h2 style={{ marginTop: 0 }}>This page could not be displayed</h2>
          <p className="err-text">{this.state.error}</p>
          <p className="muted" style={{ fontSize: 12 }}>
            Reload the console, or pick another page. Nothing was changed by the failed render.
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}
