import { describe, expect, it } from "vitest";
import { encodeCsiUKey } from "./terminalKeyboard";

const modifiers = {
  altKey: true,
  ctrlKey: true,
  metaKey: false,
  shiftKey: false,
};

describe("enhanced terminal keyboard input", () => {
  it("encodes Ctrl+Alt workspace bindings with CSI u", () => {
    expect(encodeCsiUKey("KeyP", modifiers)).toBe("\x1b[112;7u");
    expect(encodeCsiUKey("KeyN", modifiers)).toBe("\x1b[110;7u");
  });

  it("includes Shift for agent bindings", () => {
    expect(
      encodeCsiUKey("KeyP", { ...modifiers, shiftKey: true }),
    ).toBe("\x1b[112;8u");
    expect(
      encodeCsiUKey("KeyN", { ...modifiers, shiftKey: true }),
    ).toBe("\x1b[110;8u");
  });

  it("ignores unsupported physical keys", () => {
    expect(encodeCsiUKey("ArrowDown", modifiers)).toBeUndefined();
  });
});
