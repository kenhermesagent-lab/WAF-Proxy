import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { NAV } from "../nav";
import { HELP, helpFor } from "./index";
import { HelpBody } from "./render";

describe("page help", () => {
  it("covers every page in the navigation", () => {
    expect(NAV.map((n) => n.id).filter((id) => !helpFor(id))).toEqual([]);
  });

  it("does not ship help for a page that no longer exists", () => {
    const ids = new Set(NAV.map((n) => n.id));
    expect(Object.keys(HELP).filter((id) => !ids.has(id))).toEqual([]);
  });

  it("renders headings, list items and bold terms", () => {
    render(<HelpBody text={"## Concepts\n- **Ban** — an address refused\n\nA paragraph."} />);
    expect(screen.getByText("Concepts")).toBeTruthy();
    expect(screen.getByText("Ban")).toBeTruthy();
    expect(screen.getByText("A paragraph.")).toBeTruthy();
  });
});
