import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "../ui/ErrorBoundary";

function Boom(): never {
  throw new Error("render exploded");
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    // React and the boundary both log the failure; keep the test output clean.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("replaces a throwing subtree with the fallback and does not rethrow", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Something went wrong");
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    expect(alert).not.toHaveTextContent("render exploded");
  });
});
