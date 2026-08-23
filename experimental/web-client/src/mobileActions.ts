export const DEFAULT_MOBILE_ACTIONS = [
  { label: "New pane", input: "\u0002v" },
  { label: "New tab", input: "\u0002c" },
  { label: "New workspace", input: "\u0002N" },
] as const;

export function isPhoneUserAgent(userAgent: string): boolean {
  return /iPhone|iPod|Android.+Mobile|Windows Phone|IEMobile|Opera Mini|BlackBerry|webOS/i.test(
    userAgent,
  );
}
