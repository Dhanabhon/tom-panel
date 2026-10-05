// Fixture harness for the browser smoke suite. Playwright is loaded lazily:
// when it is not installed (or no fixture endpoint is configured) the suite
// degrades to a clean skip instead of failing module resolution. CI sets
// TOMPANEL_TEST_URL and installs Playwright to drive the real specs.
const base = process.env.TOMPANEL_TEST_URL;

let playwright;
try {
  playwright = await import("playwright");
} catch {
  playwright = null;
}

let test, expect;
if (!playwright || !base) {
  const { test: skipTest } = await import("node:test");
  const reason = !playwright ? "playwright is not installed" : "TOMPANEL_TEST_URL is not set";
  test = (name, _runner) => skipTest(name, { skip: reason }, () => {});
  expect = () => {};
} else {
  test = playwright.test.extend({
    login: async ({ page }, use) => {
      await page.goto(base + "/login");
      await page.getByLabel("Username").fill("admin");
      await page.getByLabel("Password").fill(process.env.TOMPANEL_TEST_PASSWORD);
      await page.keyboard.press("Enter");
      await page.getByLabel("Verification code").fill(process.env.TOMPANEL_TEST_TOTP);
      await page.keyboard.press("Enter");
      await page.waitForURL("**/");
      await use(async () => {});
    },
  });
  expect = playwright.expect;
}

export { test, expect };
