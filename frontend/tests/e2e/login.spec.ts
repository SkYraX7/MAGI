import { expect, test } from "@playwright/test";

// CLAUDE.md E2E: "Login: valid credentials grant access; invalid show an error."
// These assume the backend has an admin user configured (ADMIN_PASSWORD_HASH).

test("invalid credentials show an error", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("username").fill("admin");
  await page.getByLabel("password").fill("definitely-wrong");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("alert")).toContainText(/invalid/i);
});

test("login form renders", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  await expect(page.getByLabel("username")).toBeVisible();
  await expect(page.getByLabel("password")).toBeVisible();
});

test.skip("valid credentials grant access (requires seeded admin)", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("username").fill("admin");
  await page.getByLabel("password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: /sign in/i }).click();
  // Dashboard header brand appears once authenticated.
  await expect(page.getByText("MAGI")).toBeVisible();
});
