import { describe, expect, it, vi } from "vitest";
import { encodeSgrMouseEvent, terminalCellFromPoint } from "./terminalMouse";

const noModifiers = { altKey: false, ctrlKey: false, metaKey: false };

describe("terminal mouse input", () => {
  it("maps browser coordinates to one-based terminal cells", () => {
    const grid = document.createElement("div");
    vi.spyOn(grid, "getBoundingClientRect").mockReturnValue({
      left: 10,
      top: 20,
      right: 810,
      bottom: 420,
      width: 800,
      height: 400,
      x: 10,
      y: 20,
      toJSON: () => undefined,
    });

    expect(terminalCellFromPoint(grid, 15, 25, 80, 40)).toEqual({
      column: 1,
      row: 1,
    });
    expect(terminalCellFromPoint(grid, 809, 419, 80, 40)).toEqual({
      column: 80,
      row: 40,
    });
    expect(terminalCellFromPoint(grid, 410, 220, 80, 40)).toEqual({
      column: 41,
      row: 21,
    });
  });

  it("ignores points outside the rendered grid", () => {
    const grid = document.createElement("div");
    vi.spyOn(grid, "getBoundingClientRect").mockReturnValue({
      left: 10,
      top: 20,
      right: 110,
      bottom: 70,
      width: 100,
      height: 50,
      x: 10,
      y: 20,
      toJSON: () => undefined,
    });

    expect(terminalCellFromPoint(grid, 110, 40, 10, 5)).toBeUndefined();
  });

  it("encodes SGR press and release sequences", () => {
    const cell = { column: 12, row: 7 };

    expect(encodeSgrMouseEvent(0, true, cell, noModifiers)).toBe(
      "\x1b[<0;12;7M",
    );
    expect(encodeSgrMouseEvent(0, false, cell, noModifiers)).toBe(
      "\x1b[<0;12;7m",
    );
    expect(
      encodeSgrMouseEvent(2, true, cell, {
        altKey: true,
        ctrlKey: true,
        metaKey: false,
      }),
    ).toBe("\x1b[<26;12;7M");
  });
});
