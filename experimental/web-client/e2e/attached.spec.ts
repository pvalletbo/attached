import { expect, test } from "@playwright/test";

const generatedAssets = [
  "/src/protocol-bindings/herdr_tui_protocol.js",
  "/src/protocol-bindings/herdr_tui_protocol_bg.wasm",
  "/src/iroh-bindings/attached_browser_iroh.js",
  "/src/iroh-bindings/attached_browser_iroh_bg.wasm",
  "/src/sync-bindings/attached_browser_sync.js",
  "/src/sync-bindings/attached_browser_sync_bg.wasm",
];
const syncAssets = generatedAssets.slice(4);

test("starts with account onboarding without loading generated WASM", async ({ page }) => {
  const generatedRequests: string[] = [];
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (generatedAssets.includes(pathname)) generatedRequests.push(pathname);
  });

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Connect to your Herdr sessions" }),
  ).toBeVisible();
  await expect(page.getByLabel("Account bundle")).toBeVisible();
  await page.waitForTimeout(100);

  expect(generatedRequests).toEqual([]);
});

test("account onboarding masks the bundle and loads generated sync WASM assets on submit", async ({ page }) => {
  const assetResponses = new Map<string, { contentType: string; body: Buffer }>();
  page.on("response", async (response) => {
    const pathname = new URL(response.url()).pathname;
    if (syncAssets.includes(pathname)) {
      assetResponses.set(pathname, {
        contentType: response.headers()["content-type"] ?? "",
        body: await response.body(),
      });
    }
  });

  await page.goto("/");
  const accountBundle = page.getByLabel("Account bundle");
  await expect(accountBundle).toHaveAttribute("type", "password");
  await accountBundle.fill("aW52YWxpZC1lMmUtZml4dHVyZQ");
  await page.getByRole("button", { name: "Load sessions" }).click();

  await expect(page.getByRole("alert")).toHaveText("The account bundle is invalid.");
  await expect
    .poll(() => [...assetResponses.keys()].sort(), {
      message: "all browser sync assets loaded",
    })
    .toEqual([...syncAssets].sort());

  const syncJs = assetResponses.get("/src/sync-bindings/attached_browser_sync.js");
  const syncWasm = assetResponses.get(
    "/src/sync-bindings/attached_browser_sync_bg.wasm",
  );
  expect(syncJs?.contentType).toContain("javascript");
  expect(syncWasm?.contentType).toContain("application/wasm");
  expect(syncWasm?.body.subarray(0, 4)).toEqual(Buffer.from([0, 97, 115, 109]));
  expect(syncJs?.body.toString("utf8")).toContain("WebAssembly");
});

test("production mobile back-control styles keep a 44px touch target", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Connect to your Herdr sessions" }),
  ).toBeVisible();
  await expect(page.locator(".back-button")).toHaveCount(0);

  const minHeight = await page.evaluate(() => {
    for (const sheet of document.styleSheets) {
      for (const rule of sheet.cssRules) {
        if (
          rule instanceof CSSStyleRule &&
          rule.selectorText.split(",").some((selector) => selector.trim() === ".back-button")
        ) {
          return rule.style.minHeight;
        }
      }
    }
    return null;
  });
  expect(minHeight).toBe("44px");
});
