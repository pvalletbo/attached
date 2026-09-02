import { describe, expect, it } from "vitest";

import { CatalogValidationError, lastPublishSummary, MAX_SESSION_COUNT, parseCatalog, versionSummary } from "./catalog";

const VALID_SESSION = {
  target: "office/deep work",
  host: "office",
  session: "deep work",
  attachedVersion: [0, 3, 1],
  herdrVersion: [0, 9, 0],
  publishedAt: "2026-08-29T12:34:56Z",
};

describe("parseCatalog", () => {
  it("parses the stable Attached session boundary", () => {
    expect(parseCatalog(JSON.stringify([{ ...VALID_SESSION, ignored: true }]))).toEqual([VALID_SESSION]);
  });

  it("accepts legacy null metadata", () => {
    const session = {
      ...VALID_SESSION,
      attachedVersion: null,
      publishedAt: null,
    };

    expect(parseCatalog(JSON.stringify([session]))).toEqual([session]);
  });

  it.each([
    ["non-JSON", "not JSON"],
    ["non-array", JSON.stringify({ ...VALID_SESSION })],
    ["non-object row", JSON.stringify(["office/work"])],
    ["empty host", JSON.stringify([{ ...VALID_SESSION, host: "", target: "/deep work" }])],
    ["null byte", JSON.stringify([{ ...VALID_SESSION, session: "bad\0name", target: "office/bad\0name" }])],
    ["inconsistent target", JSON.stringify([{ ...VALID_SESSION, target: "elsewhere/deep work" }])],
    ["missing Attached version", JSON.stringify([{ ...VALID_SESSION, attachedVersion: undefined }])],
    ["invalid Herdr version", JSON.stringify([{ ...VALID_SESSION, herdrVersion: [0, -1, 0] }])],
    ["oversized version component", JSON.stringify([{ ...VALID_SESSION, attachedVersion: [0, 65_536, 0] }])],
    ["invalid publication date", JSON.stringify([{ ...VALID_SESSION, publishedAt: "yesterday-ish" }])],
  ])("rejects %s", (_name, raw) => {
    expect(() => parseCatalog(raw)).toThrow(CatalogValidationError);
  });

  it("rejects duplicate targets that would make selection ambiguous", () => {
    expect(() => parseCatalog(JSON.stringify([VALID_SESSION, VALID_SESSION]))).toThrow("duplicate session targets");
  });

  it("bounds the number of rendered sessions", () => {
    const catalog = Array.from({ length: MAX_SESSION_COUNT + 1 }, () => VALID_SESSION);

    expect(() => parseCatalog(JSON.stringify(catalog))).toThrow("too many sessions");
  });
});

describe("metadata summaries", () => {
  it("formats versions without inventing legacy metadata", () => {
    expect(versionSummary([1, 2, 3])).toBe("1.2.3");
    expect(versionSummary(null)).toBe("unknown");
  });

  it.each([
    ["2026-08-29T12:34:56Z", Date.parse("2026-08-29T12:35:25Z"), "29s ago"],
    ["2026-08-29T12:34:56Z", Date.parse("2026-08-29T12:36:56Z"), "2m ago"],
    ["2026-08-29T12:34:56Z", Date.parse("2026-08-29T15:34:56Z"), "3h ago"],
    ["2026-08-29T12:34:56Z", Date.parse("2026-08-31T12:34:56Z"), "2d ago"],
    ["2026-08-29T12:35:56Z", Date.parse("2026-08-29T12:34:56Z"), "clock skew"],
    [null, Date.parse("2026-08-29T12:34:56Z"), "unknown"],
  ])("formats last-publish age", (publishedAt, now, expected) => {
    expect(lastPublishSummary(publishedAt, now)).toBe(expected);
  });
});
