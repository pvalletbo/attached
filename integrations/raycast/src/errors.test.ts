import { describe, expect, it } from "vitest";

import { AttachedNotFoundError, CatalogCommandError, InvalidAttachedPathError } from "./attached";
import { CatalogValidationError } from "./catalog";
import { displayError } from "./errors";

describe("displayError", () => {
  it("gives actionable installation and preference guidance", () => {
    expect(displayError(new AttachedNotFoundError(["/secret/home/.local/bin/attached"]), "password")).toEqual({
      kind: "missing",
      title: "Attached Isn't Installed",
      message: "Install Attached, or set its absolute executable path in this extension's preferences.",
    });
    expect(displayError(new InvalidAttachedPathError(), "password").kind).toBe("preference");
  });

  it("turns password failures into a retry prompt", () => {
    const rendered = displayError(new CatalogCommandError("exit", "password", "authentication", 1), "password");

    expect(rendered.kind).toBe("authentication");
    expect(rendered.message).toContain("Enter it again");
  });

  it("turns 1Password failures into unlock guidance", () => {
    const rendered = displayError(new CatalogCommandError("exit", "1password", "one-password", 1), "1password");

    expect(rendered.kind).toBe("one-password");
    expect(rendered.message).toContain("authorize its CLI");
  });

  it("asks for an Attached update when the catalog command is unavailable", () => {
    const rendered = displayError(new CatalogCommandError("exit", "password", "unsupported", 2), "password");

    expect(rendered.title).toBe("Attached Must Be Updated");
    expect(rendered.message).toContain("machine-readable attached sessions");
  });

  it("does not expose parser details in the user-facing error", () => {
    const rendered = displayError(new CatalogValidationError("row 1 contained secret-host/session"), "password");

    expect(rendered.kind).toBe("catalog");
    expect(JSON.stringify(rendered)).not.toContain("secret-host");
  });
});
