export interface TerminalCell {
  column: number;
  row: number;
}

export interface MouseModifiers {
  altKey: boolean;
  ctrlKey: boolean;
  metaKey: boolean;
}

export function terminalCellFromPoint(
  grid: HTMLElement,
  clientX: number,
  clientY: number,
  columns: number,
  rows: number,
): TerminalCell | undefined {
  const bounds = grid.getBoundingClientRect();
  if (
    columns < 1 ||
    rows < 1 ||
    bounds.width <= 0 ||
    bounds.height <= 0 ||
    clientX < bounds.left ||
    clientX >= bounds.right ||
    clientY < bounds.top ||
    clientY >= bounds.bottom
  ) {
    return undefined;
  }

  return {
    column: Math.min(columns, Math.floor(((clientX - bounds.left) / bounds.width) * columns) + 1),
    row: Math.min(rows, Math.floor(((clientY - bounds.top) / bounds.height) * rows) + 1),
  };
}

export function encodeSgrMouseEvent(
  button: number,
  pressed: boolean,
  cell: TerminalCell,
  modifiers: MouseModifiers,
): string | undefined {
  if (button < 0 || button > 2) return undefined;

  let code = button;
  if (modifiers.altKey || modifiers.metaKey) code += 8;
  if (modifiers.ctrlKey) code += 16;

  return `\x1b[<${code};${cell.column};${cell.row}${pressed ? "M" : "m"}`;
}
