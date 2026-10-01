// Minimal fixture harness wrapper. The specs import test/expect from here so
// the suite stays runnable under `node --test` when Playwright is installed.
import { test as playwrightTest, expect } from "playwright/test";

const base = process.env.TOMPANEL_TEST_URL;

export const test = playwrightTest.extend({
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

export { expect };
