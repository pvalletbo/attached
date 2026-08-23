import { screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wterm/react", () => ({
  useTerminal: () => ({
    ref: { current: null },
    write: vi.fn(),
    focus: vi.fn(),
  }),
  Terminal: () => <div aria-label="Real Herdr terminal" />,
}));

let unmountCurrentEntry: (() => void) | undefined;

async function importEntry(): Promise<void> {
  const { attachedUnmount } = await import("./main");
  unmountCurrentEntry = attachedUnmount;
}

describe("Attached entry module", () => {
  beforeEach(() => {
    vi.resetModules();
    document.body.innerHTML = '<div id="attached-root"></div>';
    window.history.replaceState(null, "", "/");
  });

  afterEach(() => {
    unmountCurrentEntry?.();
    unmountCurrentEntry = undefined;
  });

  it("always starts with synchronized-account onboarding", async () => {
    await importEntry();

    expect(
      await screen.findByRole("heading", { name: "Connect to your Herdr sessions" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Account bundle")).toBeVisible();
  });
});
