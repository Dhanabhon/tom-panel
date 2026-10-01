// TomPanel browser smoke coverage against a private-endpoint fixture.
//
// The suite covers login with TOTP, keyboard navigation, the site creation
// flows, job progress, and the exact-name plus step-up confirmation for
// destructive actions. It runs against a fixture endpoint provided through
// TOMPANEL_TEST_URL and uses the shared Playwright browser install.
import { test, expect } from "./harness.mjs";

// The specs below execute when the fixture environment is present; CI
// provides TOMPANEL_TEST_URL, TOTP seed, and recovery codes.
if (!process.env.TOMPANEL_TEST_URL) {
  console.log("TOMPANEL_TEST_URL not set; browser smoke skipped");
  process.exit(0);
}

test("login with TOTP reaches the dashboard", async ({ page }) => {
  await page.goto(process.env.TOMPANEL_TEST_URL + "/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(process.env.TOMPANEL_TEST_PASSWORD);
  await page.keyboard.press("Enter");
  await page.getByLabel("Verification code").fill(process.env.TOMPANEL_TEST_TOTP);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});

test("keyboard navigation reaches every main section", async ({ page, login }) => {
  await login();
  for (const section of ["Sites", "Domains & SSL", "Services", "Activity", "System", "Settings"]) {
    await page.getByRole("link", { name: section }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  }
});

test("static site creation flow shows job progress", async ({ page, login }) => {
  await login();
  await page.getByRole("link", { name: "Sites" }).click();
  await page.getByRole("link", { name: "Create site" }).click();
  await page.getByLabel("Site type").selectOption("static");
  await page.getByLabel("Primary domain").fill("smoke.example.test");
  await page.getByRole("button", { name: "Create and provision" }).click();
  await expect(page.getByText("Server task queued")).toBeVisible();
});

test("destructive site deletion needs exact name and step-up", async ({ page, login }) => {
  await login();
  await page.goto(process.env.TOMPANEL_TEST_URL + "/sites/" + process.env.TOMPANEL_TEST_SITE + "/backups");
  await page.getByLabel(/Type/).fill("smoke.example.test");
  await page.getByRole("radio", { name: /Release TomPanel-owned/ }).check();
  await page.getByRole("button", { name: "Delete site" }).click();
  // The first attempt without recent verification must be refused.
  await expect(page.getByText(/recent verification/i)).toBeVisible();
});
