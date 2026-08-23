export interface KeyModifiers {
  altKey: boolean;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
}

export function encodeCsiUKey(
  code: string,
  modifiers: KeyModifiers,
): string | undefined {
  const letter = /^Key([A-Z])$/.exec(code)?.[1];
  const digit = /^Digit([0-9])$/.exec(code)?.[1];
  const key = letter?.toLowerCase() ?? digit;
  if (key === undefined) return undefined;

  let modifier = 1;
  if (modifiers.shiftKey) modifier += 1;
  if (modifiers.altKey) modifier += 2;
  if (modifiers.ctrlKey) modifier += 4;
  if (modifiers.metaKey) modifier += 8;

  return `\x1b[${key.codePointAt(0)};${modifier}u`;
}
