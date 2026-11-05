import { test, expect } from '@playwright/test';

test('Sauce Guard security screen remains private and login preserves product branding', async ({ page }) => {
  await page.goto('/founder/sauce-guard');
  await expect(page).toHaveURL(/\/founder$/);
  await expect(page.getByRole('heading', { name: 'Founder sign in' })).toBeVisible();
  const css = await page.locator('style').textContent();
  expect(css).toContain('#c9973f');
  await expect(page.getByRole('link', { name: 'Open security console' })).toHaveCount(0);
});
